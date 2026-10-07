//! Proof systems this binary can verify against.
//!
//! A proof system turns proof bytes into the bytes the guest committed to. Whether those are the
//! right public input is decided in [`crate::public_input`].

pub mod sp1;
pub mod zisk;

use std::fmt::Display;

use serde::{Deserialize, Serialize, de::DeserializeOwned};

/// Ceiling on what a length prefix inside a proof can allocate.
///
/// A guard, not a size bound. bincode counts an in-memory claim, which can exceed the wire size, so
/// `MAX_PROOF_SIZE` here would refuse proofs the spec admits. `ere` uses 64 MiB too.
const MAX_DECODE_BYTES: usize = 64 * 1024 * 1024;

/// Decode a proof in bincode's legacy encoding, which `ere`'s provers write, with nothing left over.
fn decode_legacy<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, Rejection> {
    let (value, consumed) = bincode::serde::decode_from_slice(
        bytes,
        bincode::config::legacy().with_limit::<MAX_DECODE_BYTES>(),
    )
    .map_err(Rejection::malformed)?;
    if consumed != bytes.len() {
        return Err(Rejection::malformed("trailing bytes after the proof"));
    }
    Ok(value)
}

/// A verifier bound to one compiled guest program.
pub trait ProofVerifier: Send + Sync + 'static {
    /// Verify `proof` and return the bytes the guest committed to.
    fn verify(&self, proof: &[u8]) -> Result<Vec<u8>, Rejection>;
}

/// Why a proof was not accepted. Both answer `INVALID`, but only `Unverified` says anything about a
/// payload.
#[derive(Debug, thiserror::Error)]
pub enum Rejection {
    /// Not a proof of the shape this proof system expects.
    #[error("{0}")]
    Malformed(String),
    /// Well formed, and does not verify.
    #[error("{0}")]
    Unverified(String),
}

impl Rejection {
    pub fn malformed(reason: impl Display) -> Self {
        Self::Malformed(reason.to_string())
    }

    pub fn unverified(reason: impl Display) -> Self {
        Self::Unverified(reason.to_string())
    }
}

/// A verifying key that does not belong to its proof system.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct InvalidProgramVk(String);

impl InvalidProgramVk {
    fn new(reason: impl Display) -> Self {
        Self(reason.to_string())
    }
}

/// The proof systems this binary was built with.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProofSystem {
    Sp1,
    Zisk,
}

impl ProofSystem {
    pub fn name(self) -> &'static str {
        match self {
            Self::Sp1 => "sp1",
            Self::Zisk => "zisk",
        }
    }

    /// Build a verifier for the program `program_vk` names.
    ///
    /// Called once per proof type at startup. SP1 builds its recursion verifier here, not per
    /// request.
    pub fn verifier(self, program_vk: &[u8]) -> Result<Box<dyn ProofVerifier>, InvalidProgramVk> {
        match self {
            Self::Sp1 => Ok(Box::new(sp1::Sp1Verifier::new(program_vk)?)),
            Self::Zisk => Ok(Box::new(zisk::ZiskVerifier::new(program_vk)?)),
        }
    }
}

impl Display for ProofSystem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}
