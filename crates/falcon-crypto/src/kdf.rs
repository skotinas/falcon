use crate::error::{CryptoError, Result};
use crate::memory::SecureArray;
use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use sha2::Sha512;
use std::io::Read;
use zeroize::Zeroize;

// Guardrails on untrusted header params: blocks both downgrade attacks and OOM DoS.
pub const MIN_MEMORY_KIB: u32 = 16 * 1024;
pub const MAX_MEMORY_KIB: u32 = 2 * 1024 * 1024;
pub const MIN_ITERATIONS: u32 = 1;
pub const MAX_ITERATIONS: u32 = 64;
pub const MIN_PARALLELISM: u32 = 1;
pub const MAX_PARALLELISM: u32 = 32;

const KEYFILE_MIX_INFO: &[u8] = b"falcon-v1-keyfile-mix";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KdfProfile {
    FastTest,
    Interactive,
    Standard,
    Paranoid,
}

impl KdfProfile {
    pub fn params(self) -> KdfParams {
        match self {
            Self::FastTest => KdfParams {
                memory_kib: 16 * 1024,
                iterations: 1,
                parallelism: 1,
            },
            Self::Interactive => KdfParams {
                memory_kib: 64 * 1024,
                iterations: 3,
                parallelism: 4,
            },
            Self::Standard => KdfParams {
                memory_kib: 256 * 1024,
                iterations: 4,
                parallelism: 4,
            },
            Self::Paranoid => KdfParams {
                memory_kib: 512 * 1024,
                iterations: 6,
                parallelism: 4,
            },
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

impl KdfParams {
    pub fn validate(&self) -> Result<()> {
        if !(MIN_MEMORY_KIB..=MAX_MEMORY_KIB).contains(&self.memory_kib) {
            return Err(CryptoError::InvalidKdfParams(format!(
                "memory_kib={} out of range [{MIN_MEMORY_KIB}, {MAX_MEMORY_KIB}]",
                self.memory_kib
            )));
        }
        if !(MIN_ITERATIONS..=MAX_ITERATIONS).contains(&self.iterations) {
            return Err(CryptoError::InvalidKdfParams(format!(
                "iterations={} out of range [{MIN_ITERATIONS}, {MAX_ITERATIONS}]",
                self.iterations
            )));
        }
        if !(MIN_PARALLELISM..=MAX_PARALLELISM).contains(&self.parallelism) {
            return Err(CryptoError::InvalidKdfParams(format!(
                "parallelism={} out of range [{MIN_PARALLELISM}, {MAX_PARALLELISM}]",
                self.parallelism
            )));
        }
        Ok(())
    }
}

pub fn hash_keyfile<R: Read>(mut reader: R) -> Result<SecureArray<32>> {
    let mut hasher = blake3::Hasher::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    buf.zeroize();
    let mut digest = *hasher.finalize().as_bytes();
    Ok(SecureArray::from_mut_array(&mut digest))
}

pub fn derive_kek(
    passphrase: &[u8],
    keyfile_hash: Option<&[u8; 32]>,
    salt: &[u8; 32],
    params: &KdfParams,
) -> Result<SecureArray<32>> {
    params.validate()?;

    let argon_params = Params::new(
        params.memory_kib,
        params.iterations,
        params.parallelism,
        Some(32),
    )
    .map_err(|e| CryptoError::InvalidKdfParams(e.to_string()))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);
    let mut kek = SecureArray::<32>::zeroed();

    if let Some(kf_hash) = keyfile_hash {
        // Length-prefix the passphrase before concatenating the keyfile digest so
        // the encoding is injective, then expand via HKDF before Argon2id.
        let mut combined = Vec::with_capacity(8 + passphrase.len() + 32);
        combined.extend_from_slice(&(passphrase.len() as u64).to_le_bytes());
        combined.extend_from_slice(passphrase);
        combined.extend_from_slice(kf_hash);

        let hk = Hkdf::<Sha512>::new(Some(salt), &combined);
        combined.zeroize();

        let mut mixed = SecureArray::<64>::zeroed();
        hk.expand(KEYFILE_MIX_INFO, mixed.as_array_mut())
            .map_err(|_| CryptoError::HkdfFailed)?;

        argon2
            .hash_password_into(mixed.as_slice(), salt, kek.as_array_mut())
            .map_err(|e| CryptoError::KdfFailed(e.to_string()))?;
    } else {
        argon2
            .hash_password_into(passphrase, salt, kek.as_array_mut())
            .map_err(|e| CryptoError::KdfFailed(e.to_string()))?;
    }

    Ok(kek)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kdf_is_deterministic_and_input_sensitive() {
        let params = KdfProfile::FastTest.params();
        let salt = [0x11u8; 32];
        let a = derive_kek(b"hunter2-not-really", None, &salt, &params).unwrap();
        let b = derive_kek(b"hunter2-not-really", None, &salt, &params).unwrap();
        let c = derive_kek(b"something-else", None, &salt, &params).unwrap();
        assert!(a.ct_eq(&b));
        assert!(!a.ct_eq(&c));
    }

    #[test]
    fn keyfile_alters_derived_kek() {
        let params = KdfProfile::FastTest.params();
        let salt = [0x22u8; 32];
        let kf = hash_keyfile(&b"some-keyfile-bytes"[..]).unwrap();
        let plain = derive_kek(b"pass", None, &salt, &params).unwrap();
        let bound = derive_kek(b"pass", Some(kf.as_array()), &salt, &params).unwrap();
        assert!(!plain.ct_eq(&bound));
    }

    #[test]
    fn rejects_weak_kdf_params() {
        let weak = KdfParams {
            memory_kib: 1024,
            iterations: 1,
            parallelism: 1,
        };
        assert!(weak.validate().is_err());
    }
}
