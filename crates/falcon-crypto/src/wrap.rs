use crate::error::{CryptoError, Result};
use crate::memory::SecureArray;
use crate::xts::{CipherMode, XtsCipher};
use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use ed25519_dalek::{SigningKey, VerifyingKey};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::Sha512;
use subtle::ConstantTimeEq;

pub const MASTER_SECRET_SIZE: usize = 64;
pub const WRAPPED_SECRET_SIZE: usize = MASTER_SECRET_SIZE + 16;
pub const WRAP_NONCE_SIZE: usize = 12;

const INFO_XTS_K1: &[u8] = b"falcon-v1-xts-k1";
const INFO_XTS_K2: &[u8] = b"falcon-v1-xts-k2";
const INFO_SERP_K1: &[u8] = b"falcon-v2-serpent-k1";
const INFO_SERP_K2: &[u8] = b"falcon-v2-serpent-k2";
const INFO_SECTOR_MAC: &[u8] = b"falcon-v1-sector-mac";
const INFO_HEADER_MAC: &[u8] = b"falcon-v1-header-mac";
const INFO_CUSTODY_ED25519: &[u8] = b"falcon-v3-custody-ed25519";
const DURESS_SENTINEL_DOMAIN: &[u8] = b"falcon-v2-duress-sentinel";
const HIDDEN_MASK_DOMAIN: &[u8] = b"falcon-v3-hidden-header-mask";

pub struct VolumeKeys {
    master_secret: SecureArray<MASTER_SECRET_SIZE>,
    xts_k1: SecureArray<32>,
    xts_k2: SecureArray<32>,
    serp_k1: SecureArray<32>,
    serp_k2: SecureArray<32>,
    sector_mac_key: SecureArray<32>,
    header_mac_key: SecureArray<32>,
    custody_ed25519_seed: SecureArray<32>,
}

impl VolumeKeys {
    pub fn generate(volume_uuid: &[u8; 16]) -> Result<Self> {
        let mut secret = SecureArray::<MASTER_SECRET_SIZE>::zeroed();
        OsRng.fill_bytes(secret.as_array_mut());
        Self::derive_from_secret(secret, volume_uuid)
    }

    pub fn derive_from_secret(
        master_secret: SecureArray<MASTER_SECRET_SIZE>,
        volume_uuid: &[u8; 16],
    ) -> Result<Self> {
        let hk = Hkdf::<Sha512>::new(Some(volume_uuid), master_secret.as_slice());

        let mut xts_k1 = SecureArray::<32>::zeroed();
        let mut xts_k2 = SecureArray::<32>::zeroed();
        let mut serp_k1 = SecureArray::<32>::zeroed();
        let mut serp_k2 = SecureArray::<32>::zeroed();
        let mut sector_mac_key = SecureArray::<32>::zeroed();
        let mut header_mac_key = SecureArray::<32>::zeroed();
        let mut custody_ed25519_seed = SecureArray::<32>::zeroed();

        hk.expand(INFO_XTS_K1, xts_k1.as_array_mut())
            .map_err(|_| CryptoError::HkdfFailed)?;
        hk.expand(INFO_XTS_K2, xts_k2.as_array_mut())
            .map_err(|_| CryptoError::HkdfFailed)?;
        hk.expand(INFO_SERP_K1, serp_k1.as_array_mut())
            .map_err(|_| CryptoError::HkdfFailed)?;
        hk.expand(INFO_SERP_K2, serp_k2.as_array_mut())
            .map_err(|_| CryptoError::HkdfFailed)?;
        hk.expand(INFO_SECTOR_MAC, sector_mac_key.as_array_mut())
            .map_err(|_| CryptoError::HkdfFailed)?;
        hk.expand(INFO_HEADER_MAC, header_mac_key.as_array_mut())
            .map_err(|_| CryptoError::HkdfFailed)?;
        hk.expand(INFO_CUSTODY_ED25519, custody_ed25519_seed.as_array_mut())
            .map_err(|_| CryptoError::HkdfFailed)?;

        if bool::from(xts_k1.as_slice().ct_eq(xts_k2.as_slice()))
            || bool::from(serp_k1.as_slice().ct_eq(serp_k2.as_slice()))
        {
            return Err(CryptoError::IdenticalXtsKeys);
        }

        Ok(Self {
            master_secret,
            xts_k1,
            xts_k2,
            serp_k1,
            serp_k2,
            sector_mac_key,
            header_mac_key,
            custody_ed25519_seed,
        })
    }

    pub fn master_secret(&self) -> &SecureArray<MASTER_SECRET_SIZE> {
        &self.master_secret
    }

    pub fn cipher(&self, mode: CipherMode) -> Result<XtsCipher> {
        match mode {
            CipherMode::Aes256Xts => XtsCipher::new(self.xts_k1.as_array(), self.xts_k2.as_array()),
            CipherMode::CascadeAesSerpentXts => XtsCipher::new_cascade(
                self.xts_k1.as_array(),
                self.xts_k2.as_array(),
                self.serp_k1.as_array(),
                self.serp_k2.as_array(),
            ),
        }
    }

    pub fn xts_cipher(&self) -> Result<XtsCipher> {
        self.cipher(CipherMode::Aes256Xts)
    }

    pub fn sector_mac_key(&self) -> &[u8; 32] {
        self.sector_mac_key.as_array()
    }

    pub fn header_mac_key(&self) -> &[u8; 32] {
        self.header_mac_key.as_array()
    }

    pub fn custody_signing_key(&self) -> SigningKey {
        SigningKey::from_bytes(self.custody_ed25519_seed.as_array())
    }

    pub fn custody_verifying_key(&self) -> VerifyingKey {
        self.custody_signing_key().verifying_key()
    }
}

/// Applies/removes a BLAKE3 XOF keystream mask over a hidden volume header so
/// zero plaintext magic bytes (`FLCNDSK1`) appear anywhere inside the outer volume.
pub fn apply_hidden_header_mask(mask_key: &SecureArray<32>, salt: &[u8; 32], buf: &mut [u8]) {
    let mut h = blake3::Hasher::new_keyed(mask_key.as_array());
    h.update(HIDDEN_MASK_DOMAIN);
    h.update(salt);
    let mut reader = h.finalize_xof();
    let mut chunk = [0u8; 256];
    let mut pos = 0;
    while pos < buf.len() {
        let take = (buf.len() - pos).min(chunk.len());
        reader.fill(&mut chunk[..take]);
        for i in 0..take {
            buf[pos + i] ^= chunk[i];
        }
        pos += take;
    }
    zeroize::Zeroize::zeroize(&mut chunk);
}

// Deterministic 32-byte sentinel bound to volume UUID. Wrapped inside a normal-looking
// key slot so duress slots cannot be distinguished from real slots on disk.
pub fn duress_sentinel(volume_uuid: &[u8; 16]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(DURESS_SENTINEL_DOMAIN);
    h.update(volume_uuid);
    *h.finalize().as_bytes()
}

pub fn build_duress_payload(volume_uuid: &[u8; 16]) -> SecureArray<MASTER_SECRET_SIZE> {
    let mut raw = [0u8; MASTER_SECRET_SIZE];
    raw[..32].copy_from_slice(&duress_sentinel(volume_uuid));
    OsRng.fill_bytes(&mut raw[32..]);
    SecureArray::from_mut_array(&mut raw)
}

pub fn is_duress_payload(unwrapped: &SecureArray<MASTER_SECRET_SIZE>, volume_uuid: &[u8; 16]) -> bool {
    let expected = duress_sentinel(volume_uuid);
    bool::from(unwrapped.as_slice()[..32].ct_eq(&expected))
}

pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    OsRng.fill_bytes(&mut out);
    out
}

pub fn wrap_master_secret(
    kek: &SecureArray<32>,
    nonce: &[u8; WRAP_NONCE_SIZE],
    aad: &[u8],
    master_secret: &SecureArray<MASTER_SECRET_SIZE>,
) -> Result<[u8; WRAPPED_SECRET_SIZE]> {
    let cipher = Aes256Gcm::new_from_slice(kek.as_slice()).map_err(|_| CryptoError::WrapFailed)?;
    let ct = cipher
        .encrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: master_secret.as_slice(),
                aad,
            },
        )
        .map_err(|_| CryptoError::WrapFailed)?;

    if ct.len() != WRAPPED_SECRET_SIZE {
        return Err(CryptoError::WrapFailed);
    }

    let mut out = [0u8; WRAPPED_SECRET_SIZE];
    out.copy_from_slice(&ct);
    Ok(out)
}

pub fn unwrap_master_secret(
    kek: &SecureArray<32>,
    nonce: &[u8; WRAP_NONCE_SIZE],
    aad: &[u8],
    wrapped: &[u8; WRAPPED_SECRET_SIZE],
) -> Result<SecureArray<MASTER_SECRET_SIZE>> {
    let cipher =
        Aes256Gcm::new_from_slice(kek.as_slice()).map_err(|_| CryptoError::UnwrapFailed)?;
    let mut pt = cipher
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: wrapped.as_slice(),
                aad,
            },
        )
        .map_err(|_| CryptoError::UnwrapFailed)?;

    let res = SecureArray::<MASTER_SECRET_SIZE>::from_slice(&pt).ok_or(CryptoError::UnwrapFailed);
    zeroize::Zeroize::zeroize(&mut pt);
    res
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrap_unwrap_and_duress_sentinel() {
        let uuid = random_bytes::<16>();
        let keys = VolumeKeys::generate(&uuid).unwrap();
        let mut raw_kek = random_bytes::<32>();
        let kek = SecureArray::from_mut_array(&mut raw_kek);
        let nonce = random_bytes::<WRAP_NONCE_SIZE>();

        let wrapped = wrap_master_secret(&kek, &nonce, b"slot-0", keys.master_secret()).unwrap();
        let unwrapped = unwrap_master_secret(&kek, &nonce, b"slot-0", &wrapped).unwrap();
        assert!(unwrapped.ct_eq(keys.master_secret()));
        assert!(!is_duress_payload(&unwrapped, &uuid));

        let duress = build_duress_payload(&uuid);
        assert!(is_duress_payload(&duress, &uuid));
        assert!(!is_duress_payload(&duress, &random_bytes::<16>()));
    }
}
