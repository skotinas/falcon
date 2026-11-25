use crate::error::{CryptoError, Result};
use aes::cipher::KeyInit;
use aes::Aes256;
use serpent::Serpent;
use subtle::ConstantTimeEq;
use xts_mode::{get_tweak_default, Xts128};

pub const SECTOR_SIZE: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherMode {
    Aes256Xts,
    CascadeAesSerpentXts,
}

impl CipherMode {
    pub fn display_name(self) -> &'static str {
        match self {
            Self::Aes256Xts => "AES-256-XTS",
            Self::CascadeAesSerpentXts => "AES-256-XTS + Serpent-256-XTS (Cascade)",
        }
    }
}

pub struct XtsCipher {
    aes: Xts128<Aes256>,
    serpent: Option<Xts128<Serpent>>,
}

impl XtsCipher {
    pub fn new(k1: &[u8; 32], k2: &[u8; 32]) -> Result<Self> {
        // FIPS 140-3 IG C.I forbids identical data and tweak keys.
        if bool::from(k1.ct_eq(k2)) {
            return Err(CryptoError::IdenticalXtsKeys);
        }
        let c1 = Aes256::new_from_slice(k1).map_err(|_| CryptoError::InvalidKeyLength {
            expected: 32,
            actual: k1.len(),
        })?;
        let c2 = Aes256::new_from_slice(k2).map_err(|_| CryptoError::InvalidKeyLength {
            expected: 32,
            actual: k2.len(),
        })?;
        Ok(Self {
            aes: Xts128::new(c1, c2),
            serpent: None,
        })
    }

    pub fn new_cascade(
        aes_k1: &[u8; 32],
        aes_k2: &[u8; 32],
        serp_k1: &[u8; 32],
        serp_k2: &[u8; 32],
    ) -> Result<Self> {
        let mut base = Self::new(aes_k1, aes_k2)?;
        if bool::from(serp_k1.ct_eq(serp_k2)) {
            return Err(CryptoError::IdenticalXtsKeys);
        }
        let s1 = Serpent::new_from_slice(serp_k1).map_err(|_| CryptoError::InvalidKeyLength {
            expected: 32,
            actual: serp_k1.len(),
        })?;
        let s2 = Serpent::new_from_slice(serp_k2).map_err(|_| CryptoError::InvalidKeyLength {
            expected: 32,
            actual: serp_k2.len(),
        })?;
        base.serpent = Some(Xts128::new(s1, s2));
        Ok(base)
    }

    pub fn mode(&self) -> CipherMode {
        if self.serpent.is_some() {
            CipherMode::CascadeAesSerpentXts
        } else {
            CipherMode::Aes256Xts
        }
    }

    pub fn encrypt_sector(&self, sector_index: u64, buf: &mut [u8]) -> Result<()> {
        if buf.len() != SECTOR_SIZE {
            return Err(CryptoError::InvalidSectorLength {
                expected: SECTOR_SIZE,
                actual: buf.len(),
            });
        }
        let tweak = get_tweak_default(sector_index as u128);
        self.aes.encrypt_sector(buf, tweak);
        if let Some(serp) = &self.serpent {
            serp.encrypt_sector(buf, tweak);
        }
        Ok(())
    }

    pub fn decrypt_sector(&self, sector_index: u64, buf: &mut [u8]) -> Result<()> {
        if buf.len() != SECTOR_SIZE {
            return Err(CryptoError::InvalidSectorLength {
                expected: SECTOR_SIZE,
                actual: buf.len(),
            });
        }
        let tweak = get_tweak_default(sector_index as u128);
        if let Some(serp) = &self.serpent {
            serp.decrypt_sector(buf, tweak);
        }
        self.aes.decrypt_sector(buf, tweak);
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn encrypt_data_unit(&self, seq_num: u128, data: &mut [u8]) {
        self.aes.encrypt_sector(data, get_tweak_default(seq_num));
    }

    #[cfg(test)]
    pub(crate) fn decrypt_data_unit(&self, seq_num: u128, data: &mut [u8]) {
        self.aes.decrypt_sector(data, get_tweak_default(seq_num));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_identical_keys() {
        let k = [0xAAu8; 32];
        assert!(matches!(
            XtsCipher::new(&k, &k),
            Err(CryptoError::IdenticalXtsKeys)
        ));
        assert!(matches!(
            XtsCipher::new_cascade(&[1u8; 32], &[2u8; 32], &k, &k),
            Err(CryptoError::IdenticalXtsKeys)
        ));
    }

    #[test]
    fn cascade_aes_serpent_round_trip_differs_from_aes_only() {
        let k1 = [0x11u8; 32];
        let k2 = [0x22u8; 32];
        let s1 = [0x33u8; 32];
        let s2 = [0x44u8; 32];

        let aes_only = XtsCipher::new(&k1, &k2).unwrap();
        let cascade = XtsCipher::new_cascade(&k1, &k2, &s1, &s2).unwrap();

        let pt = [0x5Au8; SECTOR_SIZE];
        let mut ct_aes = pt;
        let mut ct_cas = pt;
        aes_only.encrypt_sector(9, &mut ct_aes).unwrap();
        cascade.encrypt_sector(9, &mut ct_cas).unwrap();

        assert_ne!(ct_aes, ct_cas);
        assert_ne!(ct_cas, pt);

        cascade.decrypt_sector(9, &mut ct_cas).unwrap();
        assert_eq!(ct_cas, pt);
    }

    #[test]
    fn sector_round_trip_and_tweak_isolation() {
        let cipher = XtsCipher::new(&[0x11u8; 32], &[0x22u8; 32]).unwrap();
        let original = [0x5Au8; SECTOR_SIZE];
        let mut s0 = original;
        let mut s1 = original;

        cipher.encrypt_sector(0, &mut s0).unwrap();
        cipher.encrypt_sector(1, &mut s1).unwrap();
        assert_ne!(s0, original);
        assert_ne!(s0, s1);

        let mut wrong = s0;
        cipher.decrypt_sector(1, &mut wrong).unwrap();
        assert_ne!(wrong, original);

        cipher.decrypt_sector(0, &mut s0).unwrap();
        cipher.decrypt_sector(1, &mut s1).unwrap();
        assert_eq!(s0, original);
        assert_eq!(s1, original);
    }

    #[test]
    fn ieee_p1619_vector_10() {
        let k1: [u8; 32] = [
            0x27, 0x18, 0x28, 0x18, 0x28, 0x45, 0x90, 0x45, 0x23, 0x53, 0x60, 0x28, 0x74, 0x71,
            0x35, 0x26, 0x62, 0x49, 0x77, 0x57, 0x24, 0x70, 0x93, 0x69, 0x99, 0x59, 0x57, 0x49,
            0x66, 0x96, 0x76, 0x27,
        ];
        let k2: [u8; 32] = [
            0x31, 0x41, 0x59, 0x26, 0x53, 0x58, 0x97, 0x93, 0x23, 0x84, 0x62, 0x64, 0x33, 0x83,
            0x27, 0x95, 0x02, 0x88, 0x41, 0x97, 0x16, 0x93, 0x99, 0x37, 0x51, 0x05, 0x82, 0x09,
            0x74, 0x94, 0x45, 0x92,
        ];
        let pt: [u8; 32] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ];
        let expected: [u8; 32] = [
            0x1c, 0x3b, 0x3a, 0x10, 0x2f, 0x77, 0x03, 0x86, 0xe4, 0x83, 0x6c, 0x99, 0xe3, 0x70,
            0xcf, 0x9b, 0xea, 0x00, 0x80, 0x3f, 0x5e, 0x48, 0x23, 0x57, 0xa4, 0xae, 0x12, 0xd4,
            0x14, 0xa3, 0xe6, 0x3b,
        ];

        let cipher = XtsCipher::new(&k1, &k2).unwrap();
        let mut buf = pt;
        cipher.encrypt_data_unit(0xff, &mut buf);
        assert_eq!(buf, expected);

        cipher.decrypt_data_unit(0xff, &mut buf);
        assert_eq!(buf, pt);
    }
}
