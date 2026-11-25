use crate::error::{CryptoError, Result};
use crate::memory::SecureArray;
use hkdf::Hkdf;
use ml_kem::kem::{Decapsulate, Encapsulate};
use ml_kem::{Ciphertext, EncodedSizeUser, KemCore, MlKem1024, MlKem1024Params};
use rand::rngs::OsRng;
use sha2::Sha512;
use zeroize::Zeroize;

pub const PQ_KEYFILE_MAGIC: [u8; 8] = *b"FLCNPQ01";
pub const PQ_EK_SIZE: usize = 1568;
pub const PQ_DK_SIZE: usize = 3168;
pub const PQ_CT_SIZE: usize = 1568;
pub const PQ_KEYFILE_SIZE: usize = 8 + PQ_EK_SIZE + PQ_DK_SIZE;

const HYBRID_KEK_INFO: &[u8] = b"falcon-v2-pq-hybrid-kek";

pub struct PqKeypair {
    pub ek: [u8; PQ_EK_SIZE],
    pub dk: SecureArray<PQ_DK_SIZE>,
}

impl PqKeypair {
    pub fn generate() -> Self {
        let (dk, ek) = MlKem1024::generate(&mut OsRng);
        let ek_bytes = ek.as_bytes();
        let mut dk_bytes = dk.as_bytes();

        let mut ek_arr = [0u8; PQ_EK_SIZE];
        ek_arr.copy_from_slice(ek_bytes.as_slice());

        let mut dk_raw = [0u8; PQ_DK_SIZE];
        dk_raw.copy_from_slice(dk_bytes.as_slice());
        dk_bytes.zeroize();

        Self {
            ek: ek_arr,
            dk: SecureArray::from_mut_array(&mut dk_raw),
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(PQ_KEYFILE_SIZE);
        out.extend_from_slice(&PQ_KEYFILE_MAGIC);
        out.extend_from_slice(&self.ek);
        out.extend_from_slice(self.dk.as_slice());
        out
    }

    pub fn from_bytes(raw: &[u8]) -> Result<Self> {
        if raw.len() != PQ_KEYFILE_SIZE || raw[0..8] != PQ_KEYFILE_MAGIC {
            return Err(CryptoError::PostQuantumError(
                "invalid ML-KEM-1024 keyfile format".to_string(),
            ));
        }
        let mut ek = [0u8; PQ_EK_SIZE];
        ek.copy_from_slice(&raw[8..8 + PQ_EK_SIZE]);

        let dk = SecureArray::<PQ_DK_SIZE>::from_slice(&raw[8 + PQ_EK_SIZE..])
            .ok_or_else(|| CryptoError::PostQuantumError("bad decapsulation key length".into()))?;

        Ok(Self { ek, dk })
    }
}

pub fn pq_encapsulate(ek_bytes: &[u8; PQ_EK_SIZE]) -> Result<([u8; PQ_CT_SIZE], SecureArray<32>)> {
    let encoded_ek = ml_kem::Encoded::<ml_kem::kem::EncapsulationKey<MlKem1024Params>>::try_from(
        ek_bytes.as_slice(),
    )
    .map_err(|_| CryptoError::PostQuantumError("invalid ML-KEM-1024 public key".into()))?;
    let ek = ml_kem::kem::EncapsulationKey::<MlKem1024Params>::from_bytes(&encoded_ek);

    let (ct, mut ss) = ek
        .encapsulate(&mut OsRng)
        .map_err(|_| CryptoError::PostQuantumError("encapsulation failed".into()))?;

    let mut ct_arr = [0u8; PQ_CT_SIZE];
    ct_arr.copy_from_slice(ct.as_slice());

    let mut ss_raw = [0u8; 32];
    ss_raw.copy_from_slice(ss.as_slice());
    ss.zeroize();

    Ok((ct_arr, SecureArray::from_mut_array(&mut ss_raw)))
}

pub fn pq_decapsulate(
    dk_bytes: &SecureArray<PQ_DK_SIZE>,
    ct_bytes: &[u8; PQ_CT_SIZE],
) -> Result<SecureArray<32>> {
    let encoded_dk = ml_kem::Encoded::<ml_kem::kem::DecapsulationKey<MlKem1024Params>>::try_from(
        dk_bytes.as_slice(),
    )
    .map_err(|_| CryptoError::PostQuantumError("invalid ML-KEM-1024 secret key".into()))?;
    let dk = ml_kem::kem::DecapsulationKey::<MlKem1024Params>::from_bytes(&encoded_dk);

    let ct = Ciphertext::<MlKem1024>::try_from(ct_bytes.as_slice())
        .map_err(|_| CryptoError::PostQuantumError("invalid ML-KEM-1024 ciphertext".into()))?;

    let mut ss = dk
        .decapsulate(&ct)
        .map_err(|_| CryptoError::PostQuantumError("decapsulation failed".into()))?;

    let mut ss_raw = [0u8; 32];
    ss_raw.copy_from_slice(ss.as_slice());
    ss.zeroize();

    Ok(SecureArray::from_mut_array(&mut ss_raw))
}

// Combine classical Argon2id KEK and ML-KEM-1024 shared secret so an adversary
// must break BOTH classical and post-quantum layers to recover the master secret.
pub fn combine_hybrid_kek(
    classical_kek: &SecureArray<32>,
    pq_shared_secret: &SecureArray<32>,
    salt: &[u8; 32],
) -> Result<SecureArray<32>> {
    let mut ikm = [0u8; 64];
    ikm[..32].copy_from_slice(classical_kek.as_slice());
    ikm[32..].copy_from_slice(pq_shared_secret.as_slice());

    let hk = Hkdf::<Sha512>::new(Some(salt), &ikm);
    ikm.zeroize();

    let mut hybrid = SecureArray::<32>::zeroed();
    hk.expand(HYBRID_KEK_INFO, hybrid.as_array_mut())
        .map_err(|_| CryptoError::HkdfFailed)?;
    Ok(hybrid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ml_kem_1024_round_trip_and_hybrid_kek() {
        let kp = PqKeypair::generate();
        let serialized = kp.to_bytes();
        let loaded = PqKeypair::from_bytes(&serialized).unwrap();

        let (ct, ss_enc) = pq_encapsulate(&loaded.ek).unwrap();
        let ss_dec = pq_decapsulate(&loaded.dk, &ct).unwrap();
        assert!(ss_enc.ct_eq(&ss_dec));

        let classical = SecureArray::<32>::from_slice(&[0x42u8; 32]).unwrap();
        let salt = [0x99u8; 32];
        let h1 = combine_hybrid_kek(&classical, &ss_enc, &salt).unwrap();
        let h2 = combine_hybrid_kek(&classical, &ss_dec, &salt).unwrap();
        assert!(h1.ct_eq(&h2));
        assert!(!h1.ct_eq(&classical));
    }
}
