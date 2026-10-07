//! The ZisK backend against a real proof.
//!
//! The fixture is a genuine ZisK v1.2.0-alpha compressed proof, its program's verifying key, and the
//! public values its guest committed to, taken from `eth-act/ere` v0.18.1's `ere-verifier-zisk` test
//! fixtures (dual licensed Apache-2.0 OR MIT, the same as this crate). Its guest is one of ere's own
//! test programs rather than a stateless validator, so its public values are not a validation result
//! — which is beside the point here. What it proves is that this crate's verifying-key decoding,
//! proof decoding and STARK verification accept a real proof and return exactly the bytes its guest
//! committed to.
//!
//! Every rejection is asserted to be of the right kind, because a proof that failed to decode and a
//! proof the cryptography turned down are not the same result: a test that only asks for an error
//! passes just as happily when the proof never reaches the verifier at all.

use eth_proof_verifier::backend::{ProofSystem, ProofVerifier, Rejection};

const PROGRAM_VK: &[u8] = include_bytes!("fixtures/program_vk.bin");
const PROOF: &[u8] = include_bytes!("fixtures/proof.bin");
const PUBLIC_VALUES: &[u8] = include_bytes!("fixtures/public_values.bin");

/// A verifying key of a different program, to check a proof is bound to its own.
const OTHER_PROGRAM_VK: &str = "a4c7e4fbff2c8aa974fbeec51e72afc5b102e0563d22abccf70e60036e044c50";

/// Public values a proof carries: the program's verifying key, then the guest's outputs.
const PROGRAM_VK_WORDS: usize = 4;
const PUBLIC_VALUE_WORDS: usize = PROGRAM_VK_WORDS + 64;

fn verifier(program_vk: &[u8]) -> Box<dyn ProofVerifier> {
    ProofSystem::Zisk
        .verifier(program_vk)
        .expect("verifying key decodes")
}

fn rejection(program_vk: &[u8], proof: &[u8]) -> Rejection {
    verifier(program_vk)
        .verify(proof)
        .expect_err("must be rejected")
}

/// The reason, having established the cryptography is what turned the proof down.
fn unverified(rejection: Rejection) -> String {
    match rejection {
        Rejection::Unverified(reason) => reason,
        Rejection::Malformed(reason) => {
            panic!("expected a verification failure, but it never decoded: {reason}")
        }
    }
}

/// The reason, having established the proof was turned away before any verification.
fn malformed(rejection: Rejection) -> String {
    match rejection {
        Rejection::Malformed(reason) => reason,
        Rejection::Unverified(reason) => {
            panic!("expected a decoding failure, but it was verified: {reason}")
        }
    }
}

/// Where the public values start in the serialised proof: after the length-prefixed proof words,
/// and their own length prefix.
fn public_values_offset() -> usize {
    let proof_words = u64::from_le_bytes(PROOF[..8].try_into().expect("8 bytes"));
    let offset = 8 + 8 * proof_words as usize;
    let declared = u64::from_le_bytes(PROOF[offset..offset + 8].try_into().expect("8 bytes"));
    assert_eq!(declared as usize, PUBLIC_VALUE_WORDS);
    offset + 8
}

/// The fixture with the `index`th public value replaced.
fn with_public_value(index: usize, value: u64) -> Vec<u8> {
    let at = public_values_offset() + 8 * index;
    let mut edited = PROOF.to_vec();
    edited[at..at + 8].copy_from_slice(&value.to_le_bytes());
    edited
}

fn public_value(index: usize) -> u64 {
    let at = public_values_offset() + 8 * index;
    u64::from_le_bytes(PROOF[at..at + 8].try_into().expect("8 bytes"))
}

#[test]
fn verifies_a_real_proof_and_returns_its_public_values() {
    let public_values = verifier(PROGRAM_VK)
        .verify(PROOF)
        .expect("the fixture proof verifies");

    assert_eq!(public_values, PUBLIC_VALUES);
}

#[test]
fn rejects_a_proof_under_another_program() {
    let other = hex::decode(OTHER_PROGRAM_VK).expect("hex");
    let reason = unverified(rejection(&other, PROOF));

    assert_eq!(reason, "proof is of another program");
}

/// Corrupted inside the STARK proof, well clear of the public values and the trailing fields.
#[test]
fn rejects_a_corrupted_proof() {
    let mut corrupted = PROOF.to_vec();
    let middle = public_values_offset() / 2;
    corrupted[middle] ^= 0x01;

    assert_eq!(
        unverified(rejection(PROGRAM_VK, &corrupted)),
        "proof does not verify"
    );
}

/// The property everything else rests on: the public values a proof carries are authenticated by
/// the proof, so they cannot be edited in flight.
///
/// This crate decides whether a proof answers the beacon node's question by comparing the public
/// values the verifier returns against the public input the beacon node derived. Were those bytes
/// merely carried alongside the proof rather than committed to by it, anyone could take a valid
/// proof of one payload and relabel it as a proof of another, and the comparison would be theatre.
#[test]
fn rejects_a_proof_whose_public_values_were_edited() {
    let first_output = PROGRAM_VK_WORDS;
    let relabelled = with_public_value(first_output, public_value(first_output) ^ 0x01);

    assert_eq!(
        unverified(rejection(PROGRAM_VK, &relabelled)),
        "proof does not verify"
    );
}

/// A guest writes 32-bit outputs, so the high half of each word would otherwise go unreturned.
#[test]
fn rejects_a_public_value_wider_than_a_guest_output() {
    let first_output = PROGRAM_VK_WORDS;
    let widened = with_public_value(first_output, public_value(first_output) | 1 << 32);

    assert_eq!(
        malformed(rejection(PROGRAM_VK, &widened)),
        "a public output is wider than 32 bits"
    );
}

/// The aggregation key is for compressed proofs only.
#[test]
fn rejects_a_proof_that_claims_to_be_uncompressed() {
    let compressed_flag = public_values_offset() + 8 * PUBLIC_VALUE_WORDS;
    let mut uncompressed = PROOF.to_vec();
    assert_eq!(uncompressed[compressed_flag], 1);
    uncompressed[compressed_flag] = 0;

    let reason = malformed(rejection(PROGRAM_VK, &uncompressed));
    assert!(
        reason.starts_with("expected a compressed Poseidon1 proof"),
        "{reason}"
    );
}

#[test]
fn rejects_trailing_bytes_after_a_proof() {
    let mut padded = PROOF.to_vec();
    padded.push(0);

    assert_eq!(
        malformed(rejection(PROGRAM_VK, &padded)),
        "trailing bytes after the proof"
    );
}

/// Proof bytes arrive from the network, so a length prefix inside them must not decide how much the
/// decoder allocates. An allocation failure aborts rather than panics, which no caller can catch.
#[test]
fn rejects_a_declared_length_beyond_the_input() {
    malformed(rejection(PROGRAM_VK, &(1u64 << 60).to_le_bytes()));
}

/// Truncated and arbitrary inputs are turned away before any verification is attempted.
#[test]
fn rejects_malformed_input() {
    for input in [
        vec![],
        vec![0u8; 1],
        vec![0xAAu8; 4096],
        PROOF[..PROOF.len() - 1].to_vec(),
    ] {
        malformed(rejection(PROGRAM_VK, &input));
    }
}
