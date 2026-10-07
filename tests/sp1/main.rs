//! The SP1 backend against a real proof.
//!
//! The fixture is a genuine SP1 compressed proof, its program's verifying key, and the public values
//! its guest committed to, taken from `eth-act/ere`'s `ere-verifier-sp1` test fixtures (dual
//! licensed Apache-2.0 OR MIT, the same as this crate). Its guest is one of ere's own test programs
//! rather than a stateless validator, so its public values are not a validation result — which is
//! beside the point here. What it proves is that this crate's vendored verifying-key decoding, proof
//! decoding, exit-code check and recursion verification accept a real proof and return exactly the
//! bytes its guest committed to.
//!
//! Every rejection is asserted to be of the right kind, because a proof that failed to decode and a
//! proof the cryptography turned down are not the same result: a test that only asks for an error
//! passes just as happily when the proof never reaches the verifier at all.

use eth_proof_verifier::backend::{ProofSystem, ProofVerifier, Rejection};

const PROGRAM_VK: &[u8] = include_bytes!("fixtures/program_vk.bin");
const PROOF: &[u8] = include_bytes!("fixtures/proof.bin");
const PUBLIC_VALUES: &[u8] = include_bytes!("fixtures/public_values.bin");

/// A verifying key of a different program, to check a proof is bound to its own.
const OTHER_PROGRAM_VK: &str = "00a03cbfa95559cfee3b45ef925f3f7a631181e35e774e92b040277d893511dd";

fn verifier(program_vk: &[u8]) -> Box<dyn ProofVerifier> {
    ProofSystem::Sp1
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

    assert!(reason.contains("vk hash mismatch"), "{reason}");
}

/// Corrupted inside the proof rather than at its end: the last bytes are a version string, so
/// flipping one there fails to decode and the cryptography is never exercised.
#[test]
fn rejects_a_corrupted_proof() {
    let mut corrupted = PROOF.to_vec();
    let middle = corrupted.len() / 2;
    corrupted[middle] ^= 0x01;

    unverified(rejection(PROGRAM_VK, &corrupted));
}

/// The property everything else rests on: the public values a proof carries are authenticated by
/// the proof, so they cannot be edited in flight.
///
/// This crate decides whether a proof answers the beacon node's question by comparing the public
/// values the verifier returns against the public input the beacon node derived. Were those bytes
/// merely carried alongside the proof rather than committed to by it, anyone could take a valid
/// proof of one payload and relabel it as a proof of another, and the comparison would be theatre.
///
/// The serialised bundle holds its public values verbatim and exactly once, so this edits them
/// where they sit rather than reaching for the proof system's types.
#[test]
fn rejects_a_proof_whose_public_values_were_edited() {
    let mut relabelled = PROOF.to_vec();
    let at = relabelled
        .windows(PUBLIC_VALUES.len())
        .position(|window| window == PUBLIC_VALUES)
        .expect("the bundle carries its public values verbatim");
    relabelled[at] ^= 0x01;

    let reason = unverified(rejection(PROGRAM_VK, &relabelled));
    assert!(
        reason.contains("public values do not match the commitment"),
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
/// decoder allocates. The bytes below are a selector this decoder accepts followed by a length near
/// 2.1e17: representable, so before the decode was bounded it reached the allocator, and an
/// allocation failure aborts rather than panics, which no caller can catch.
#[test]
fn rejects_a_declared_length_beyond_the_input() {
    let mut input = 3u32.to_le_bytes().to_vec();
    input.extend_from_slice(&211_946_530_762_463_256u64.to_le_bytes());

    assert_eq!(malformed(rejection(PROGRAM_VK, &input)), "LimitExceeded");
}

/// Truncated and arbitrary inputs are turned away before any verification is attempted.
#[test]
fn rejects_malformed_input() {
    for input in [vec![], vec![0u8; 1], vec![0xAAu8; 4096]] {
        malformed(rejection(PROGRAM_VK, &input));
    }
}
