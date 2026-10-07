//! ZisK proof verification.
//!
//! The proof encoding, the proving stage and the hash family are prover conventions, not ZisK
//! itself. They follow `ere-verifier-zisk` at ere v0.18.1, which builds the `ere-guests` artifacts.

use std::array::from_fn;

use proofman_verifier::{Poseidon1Verifier, VadcopFinalProof, Verifier};

use crate::{
    backend::{InvalidProgramVk, ProofVerifier, Rejection, decode_legacy},
    registry::PROGRAM_VK_LEN,
};

/// The aggregation key every ZisK v1.2.0-alpha compressed proof is checked against: the
/// `vadcop_final_compressed.verkey.json` of that release's Poseidon1 proving key.
const VADCOP_FINAL_COMPRESSED_VK: [u64; 4] = [
    15008563959707073304,
    10715099813120081992,
    18339358923736659668,
    13838445471377553159,
];

/// The hash family [`VADCOP_FINAL_COMPRESSED_VK`] was generated under.
const HASH_FAMILY: &str = "Poseidon1";

/// Field elements in the program key a proof carries ahead of the guest's outputs.
const PROGRAM_VK_WORDS: usize = 4;

/// Output words a ZisK guest commits.
const OUTPUT_WORDS: usize = 64;

/// `2^64 - 2^32 + 1`.
const GOLDILOCKS_ORDER: u64 = 0xFFFF_FFFF_0000_0001;

/// Verifier bound to one compiled guest program.
pub struct ZiskVerifier {
    /// Merkle root of the program's ROM, which a proof carries in its first public values.
    program_vk: [u64; PROGRAM_VK_WORDS],
}

impl ZiskVerifier {
    pub fn new(program_vk: &[u8]) -> Result<Self, InvalidProgramVk> {
        Ok(Self {
            program_vk: decode_program_vk(program_vk)?,
        })
    }
}

impl ProofVerifier for ZiskVerifier {
    fn verify(&self, proof_bytes: &[u8]) -> Result<Vec<u8>, Rejection> {
        let proof: VadcopFinalProof = decode_legacy(proof_bytes)?;

        if !proof.compressed || proof.hash != HASH_FAMILY {
            return Err(Rejection::malformed(format!(
                "expected a compressed {HASH_FAMILY} proof, got {} (compressed: {})",
                proof.hash, proof.compressed
            )));
        }

        // The generated verifier reads fixed slots, so a shorter vector would panic, not fail.
        if proof.public_values.len() != PROGRAM_VK_WORDS + OUTPUT_WORDS {
            return Err(Rejection::malformed(format!(
                "expected {} public values, got {}",
                PROGRAM_VK_WORDS + OUTPUT_WORDS,
                proof.public_values.len()
            )));
        }
        let (program_vk, outputs) = proof.public_values.split_at(PROGRAM_VK_WORDS);

        // A guest writes its outputs as 32-bit words. A wider one is no output a guest made.
        let committed = outputs
            .iter()
            .map(|word| u32::try_from(*word).map(u32::to_le_bytes))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| Rejection::malformed("a public output is wider than 32 bits"))?
            .concat();

        if program_vk != self.program_vk {
            return Err(Rejection::unverified("proof is of another program"));
        }
        if !Poseidon1Verifier.verify_vadcop_final_compressed(&proof, &VADCOP_FINAL_COMPRESSED_VK) {
            return Err(Rejection::unverified("proof does not verify"));
        }

        Ok(committed)
    }
}

/// Decode the 32-byte verifying key ZisK provers publish: four little-endian Goldilocks elements.
fn decode_program_vk(bytes: &[u8]) -> Result<[u64; PROGRAM_VK_WORDS], InvalidProgramVk> {
    let bytes: &[u8; PROGRAM_VK_LEN] = bytes.try_into().map_err(|_| {
        InvalidProgramVk::new(format!(
            "expected {PROGRAM_VK_LEN} bytes, got {}",
            bytes.len()
        ))
    })?;
    let words: [u64; PROGRAM_VK_WORDS] =
        from_fn(|i| u64::from_le_bytes(from_fn(|j| bytes[8 * i + j])));

    // A proof's public values are canonical, so a key that is not would match no proof at all.
    if words.iter().any(|word| *word >= GOLDILOCKS_ORDER) {
        return Err(InvalidProgramVk::new("not four canonical field elements"));
    }
    Ok(words)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_a_program_vk_of_the_wrong_length() {
        assert!(decode_program_vk(&[0; 31]).is_err());
        assert!(decode_program_vk(&[0; 33]).is_err());
    }

    #[test]
    fn rejects_a_program_vk_holding_a_non_field_element() {
        let mut at_the_order = [0; PROGRAM_VK_LEN];
        at_the_order[24..].copy_from_slice(&GOLDILOCKS_ORDER.to_le_bytes());

        assert!(decode_program_vk(&at_the_order).is_err());
    }
}
