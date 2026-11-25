use crate::error::{CryptoError, Result};
use subtle::ConstantTimeEq;

pub const TAG_SIZE: usize = 32;

const SECTOR_MAC_DOMAIN: &[u8] = b"falcon-v1-sector-mac";
const HEADER_MAC_DOMAIN: &[u8] = b"falcon-v1-header-mac";

// Encrypt-then-MAC over ciphertext bound to volume UUID and sector index
// so swapped or transplanted sectors fail verification.
pub fn compute_sector_tag(
    integrity_key: &[u8; 32],
    volume_uuid: &[u8; 16],
    sector_index: u64,
    ciphertext: &[u8],
) -> [u8; TAG_SIZE] {
    let mut hasher = blake3::Hasher::new_keyed(integrity_key);
    hasher.update(SECTOR_MAC_DOMAIN);
    hasher.update(volume_uuid);
    hasher.update(&sector_index.to_le_bytes());
    hasher.update(&(ciphertext.len() as u64).to_le_bytes());
    hasher.update(ciphertext);
    *hasher.finalize().as_bytes()
}

pub fn verify_sector_tag(
    integrity_key: &[u8; 32],
    volume_uuid: &[u8; 16],
    sector_index: u64,
    ciphertext: &[u8],
    expected_tag: &[u8; TAG_SIZE],
) -> Result<()> {
    let actual = compute_sector_tag(integrity_key, volume_uuid, sector_index, ciphertext);
    if bool::from(actual.ct_eq(expected_tag)) {
        Ok(())
    } else {
        Err(CryptoError::IntegrityCheckFailed)
    }
}

pub fn compute_header_mac(header_mac_key: &[u8; 32], header_body: &[u8]) -> [u8; TAG_SIZE] {
    let mut hasher = blake3::Hasher::new_keyed(header_mac_key);
    hasher.update(HEADER_MAC_DOMAIN);
    hasher.update(&(header_body.len() as u64).to_le_bytes());
    hasher.update(header_body);
    *hasher.finalize().as_bytes()
}

pub fn verify_header_mac(
    header_mac_key: &[u8; 32],
    header_body: &[u8],
    expected_mac: &[u8; TAG_SIZE],
) -> Result<()> {
    let actual = compute_header_mac(header_mac_key, header_body);
    if bool::from(actual.ct_eq(expected_mac)) {
        Ok(())
    } else {
        Err(CryptoError::IntegrityCheckFailed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catches_bitflip_sector_swap_and_wrong_uuid() {
        let key = [0x33u8; 32];
        let uuid = [0x44u8; 16];
        let mut ct = [0x55u8; 4096];

        let tag = compute_sector_tag(&key, &uuid, 7, &ct);
        verify_sector_tag(&key, &uuid, 7, &ct, &tag).unwrap();

        assert!(verify_sector_tag(&key, &uuid, 8, &ct, &tag).is_err());
        assert!(verify_sector_tag(&key, &[0x45u8; 16], 7, &ct, &tag).is_err());

        ct[2048] ^= 0x01;
        assert!(verify_sector_tag(&key, &uuid, 7, &ct, &tag).is_err());
    }
}
