//! SP1 proof verification.
//!
//! The key format, the proof encoding and the exit-code commitment are prover conventions, not SP1
//! itself. They follow `ere-verifier-sp1`, which produces the `ere-guests` artifacts.

use std::{array::from_fn, borrow::Borrow, sync::LazyLock};

use sp1_hypercube::{DIGEST_SIZE, PrimeField32};
use sp1_primitives::SP1Field;
use sp1_recursion_executor::{RECURSIVE_PROOF_NUM_PV_ELTS, RecursionPublicValues};
use sp1_verifier::{ProofFromNetwork, compressed::SP1CompressedVerifier};

use crate::{
    backend::{InvalidProgramVk, ProofVerifier, Rejection, decode_legacy},
    registry::PROGRAM_VK_LEN,
};

/// Limbs the packed verifying key is held in.
const PROGRAM_VK_LIMBS: usize = PROGRAM_VK_LEN / 8;

/// Bits per field element in the packed verifying key.
const WORD_BITS: u32 = 31;

/// Shared by every SP1 proof type. Building it is the expensive part.
static RECURSION_VERIFIER: LazyLock<SP1CompressedVerifier> =
    LazyLock::new(SP1CompressedVerifier::new);

/// Verifier bound to one compiled guest program.
pub struct Sp1Verifier {
    /// Poseidon2 digest of the program's SP1 verifying key.
    program_vk: [SP1Field; DIGEST_SIZE],
}

impl Sp1Verifier {
    pub fn new(program_vk: &[u8]) -> Result<Self, InvalidProgramVk> {
        LazyLock::force(&RECURSION_VERIFIER);
        Ok(Self {
            program_vk: decode_program_vk(program_vk)?,
        })
    }
}

impl ProofVerifier for Sp1Verifier {
    fn verify(&self, proof_bytes: &[u8]) -> Result<Vec<u8>, Rejection> {
        let proof: ProofFromNetwork = decode_legacy(proof_bytes)?;

        let compressed = proof.proof.try_as_compressed_ref().ok_or_else(|| {
            Rejection::malformed(format!(
                "expected a compressed proof, got {:?}",
                proof.mode()
            ))
        })?;

        // A guest that exited non-zero never reached its commitment.
        let recursion_public_values = compressed.proof.public_values.as_slice();
        if recursion_public_values.len() != RECURSIVE_PROOF_NUM_PV_ELTS {
            return Err(Rejection::malformed(
                "proof does not commit to an exit code",
            ));
        }
        let recursion_public_values: &RecursionPublicValues<_> = recursion_public_values.borrow();
        let exit_code = recursion_public_values.exit_code.as_canonical_u32();
        if exit_code != 0 {
            return Err(Rejection::unverified(format!(
                "guest exited with code {exit_code}"
            )));
        }

        let public_values = proof.public_values.as_slice();
        RECURSION_VERIFIER
            .verify_compressed_with_public_values(compressed, public_values, &self.program_vk)
            .map_err(Rejection::unverified)?;

        Ok(public_values.to_vec())
    }
}

/// Decode the 32-byte verifying key SP1 provers publish.
///
/// `HashableKey::bytes32`: the digest's field elements as base-`2^31` digits of a big endian
/// integer, most significant first.
fn decode_program_vk(bytes: &[u8]) -> Result<[SP1Field; DIGEST_SIZE], InvalidProgramVk> {
    const WORD_MASK: u64 = (1 << WORD_BITS) - 1;

    if bytes.len() != PROGRAM_VK_LEN {
        return Err(InvalidProgramVk::new(format!(
            "expected {PROGRAM_VK_LEN} bytes, got {}",
            bytes.len()
        )));
    }

    let mut limbs: [u64; PROGRAM_VK_LIMBS] = from_fn(|i| {
        let offset = PROGRAM_VK_LEN - 8 * (i + 1);
        u64::from_be_bytes(from_fn(|j| bytes[offset + j]))
    });
    let mut words = [0u32; DIGEST_SIZE];
    for word in words.iter_mut().rev() {
        *word = (limbs[0] & WORD_MASK) as u32;
        for i in 0..PROGRAM_VK_LIMBS - 1 {
            limbs[i] = (limbs[i] >> WORD_BITS) | (limbs[i + 1] << (u64::BITS - WORD_BITS));
        }
        limbs[PROGRAM_VK_LIMBS - 1] >>= WORD_BITS;
    }

    // Leftover bits, or an element at or above the field order, means this is not a digest.
    if limbs != [0; PROGRAM_VK_LIMBS] || words.iter().any(|word| *word >= SP1Field::ORDER_U32) {
        return Err(InvalidProgramVk::new("not a canonical packed digest"));
    }
    Ok(words.map(from_canonical_u32))
}

/// Reaches `from_canonical_u32` through the bound, so this module need not import the trait.
fn from_canonical_u32<F: PrimeField32>(word: u32) -> F {
    F::from_canonical_u32(word)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_a_program_vk_of_the_wrong_length() {
        assert!(decode_program_vk(&[0; 31]).is_err());
        assert!(decode_program_vk(&[0; 33]).is_err());
    }

    /// All ones does not fit in eight 31-bit digits.
    #[test]
    fn rejects_a_program_vk_that_does_not_unpack() {
        assert!(decode_program_vk(&[0xff; 32]).is_err());
    }

    /// Why the field-order check cannot be dropped. `from_canonical_u32` reduces modulo the order
    /// behind a `debug_assert`, so in release these bytes would bind to the same program as an
    /// all-zero digest: the leading element is the order, which reduces to zero.
    #[test]
    fn rejects_a_program_vk_holding_a_non_field_element() {
        let at_the_order =
            hex::decode("00fe000002000000000000000000000000000000000000000000000000000000")
                .expect("hex");

        assert!(decode_program_vk(&at_the_order).is_err());
    }
}
