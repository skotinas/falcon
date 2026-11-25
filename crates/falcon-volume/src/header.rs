use crate::error::{Result, VolumeError};
use falcon_crypto::{
    compute_header_mac, verify_header_mac, CipherMode, KdfParams, PQ_CT_SIZE, SECTOR_SIZE,
    TAG_SIZE, WRAPPED_SECRET_SIZE, WRAP_NONCE_SIZE,
};

pub const HEADER_MAGIC: [u8; 8] = *b"FLCNDSK1";
pub const FORMAT_VERSION: u32 = 3;
pub const HEADER_SIZE: usize = 16 * 1024;
pub const MAX_KEY_SLOTS: usize = 4;
pub const KEY_SLOT_SIZE: usize = 256;
pub const KEY_SLOTS_OFFSET: usize = 128;
pub const PQ_SLOTS_OFFSET: usize = 2048;
// Bytes [16344..16352] hold the unauthenticated failed-attempt strike counter so it can be
// incremented on failed unlocks without needing header_mac_key; MAC covers [0..16344].
pub const STRIKE_COUNTER_OFFSET: usize = HEADER_SIZE - TAG_SIZE - 8;
pub const HEADER_MAC_INPUT_END: usize = STRIKE_COUNTER_OFFSET;
pub const HEADER_MAC_OFFSET: usize = HEADER_SIZE - TAG_SIZE;

pub const FLAG_INTEGRITY_ENABLED: u32 = 1 << 0;
pub const FLAG_HAS_BACKUP_HEADER: u32 = 1 << 1;
pub const FLAG_CASCADE_CIPHER: u32 = 1 << 2;
pub const FLAG_DETACHED_HEADER: u32 = 1 << 3;
pub const FLAG_HIDDEN_VOLUME: u32 = 1 << 4;

pub const SLOT_STATUS_EMPTY: u8 = 0;
pub const SLOT_STATUS_ACTIVE: u8 = 1;
pub const KDF_ALG_ARGON2ID: u8 = 1;
pub const SLOT_FLAG_REQUIRES_KEYFILE: u8 = 1 << 0;
pub const SLOT_FLAG_PQ_HYBRID: u8 = 1 << 1;

pub const MIN_DATA_SECTORS: u64 = 64; // 256 KiB floor

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeySlot {
    pub active: bool,
    pub requires_keyfile: bool,
    pub pq_hybrid: bool,
    pub kdf_params: KdfParams,
    pub salt: [u8; 32],
    pub nonce: [u8; WRAP_NONCE_SIZE],
    pub wrapped_master_secret: [u8; WRAPPED_SECRET_SIZE],
    pub pq_ciphertext: Option<Box<[u8; PQ_CT_SIZE]>>,
    pub label: String,
}

impl KeySlot {
    pub fn empty() -> Self {
        Self {
            active: false,
            requires_keyfile: false,
            pq_hybrid: false,
            kdf_params: KdfParams {
                memory_kib: 0,
                iterations: 0,
                parallelism: 0,
            },
            salt: [0u8; 32],
            nonce: [0u8; WRAP_NONCE_SIZE],
            wrapped_master_secret: [0u8; WRAPPED_SECRET_SIZE],
            pq_ciphertext: None,
            label: String::new(),
        }
    }

    pub fn slot_flags_byte(&self) -> u8 {
        let mut f = 0u8;
        if self.requires_keyfile {
            f |= SLOT_FLAG_REQUIRES_KEYFILE;
        }
        if self.pq_hybrid {
            f |= SLOT_FLAG_PQ_HYBRID;
        }
        f
    }

    pub fn serialize(&self, dst: &mut [u8; KEY_SLOT_SIZE]) {
        dst.fill(0);
        if !self.active {
            return;
        }
        dst[0] = SLOT_STATUS_ACTIVE;
        dst[1] = KDF_ALG_ARGON2ID;
        dst[2] = self.slot_flags_byte();
        dst[4..8].copy_from_slice(&self.kdf_params.memory_kib.to_le_bytes());
        dst[8..12].copy_from_slice(&self.kdf_params.iterations.to_le_bytes());
        dst[12..16].copy_from_slice(&self.kdf_params.parallelism.to_le_bytes());
        dst[16..48].copy_from_slice(&self.salt);
        dst[48..60].copy_from_slice(&self.nonce);
        dst[60..140].copy_from_slice(&self.wrapped_master_secret);

        let label_bytes = self.label.as_bytes();
        let copy_len = label_bytes.len().min(32);
        dst[140..140 + copy_len].copy_from_slice(&label_bytes[..copy_len]);
    }

    pub fn deserialize(src: &[u8; KEY_SLOT_SIZE], pq_slice: &[u8; PQ_CT_SIZE]) -> Result<Self> {
        let status = src[0];
        if status == SLOT_STATUS_EMPTY {
            return Ok(Self::empty());
        }
        if status != SLOT_STATUS_ACTIVE || src[1] != KDF_ALG_ARGON2ID {
            return Err(VolumeError::InvalidHeader);
        }

        let requires_keyfile = (src[2] & SLOT_FLAG_REQUIRES_KEYFILE) != 0;
        let pq_hybrid = (src[2] & SLOT_FLAG_PQ_HYBRID) != 0;
        let kdf_params = KdfParams {
            memory_kib: u32::from_le_bytes(src[4..8].try_into().unwrap()),
            iterations: u32::from_le_bytes(src[8..12].try_into().unwrap()),
            parallelism: u32::from_le_bytes(src[12..16].try_into().unwrap()),
        };
        kdf_params.validate()?;

        let mut salt = [0u8; 32];
        salt.copy_from_slice(&src[16..48]);

        let mut nonce = [0u8; WRAP_NONCE_SIZE];
        nonce.copy_from_slice(&src[48..60]);

        let mut wrapped_master_secret = [0u8; WRAPPED_SECRET_SIZE];
        wrapped_master_secret.copy_from_slice(&src[60..140]);

        let pq_ciphertext = if pq_hybrid {
            Some(Box::new(*pq_slice))
        } else {
            None
        };

        let raw_label = &src[140..172];
        let end = raw_label.iter().position(|&b| b == 0).unwrap_or(32);
        let label = String::from_utf8_lossy(&raw_label[..end]).to_string();

        Ok(Self {
            active: true,
            requires_keyfile,
            pq_hybrid,
            kdf_params,
            salt,
            nonce,
            wrapped_master_secret,
            pq_ciphertext,
            label,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VolumeHeader {
    pub version: u32,
    pub flags: u32,
    pub volume_uuid: [u8; 16],
    pub sector_size: u32,
    pub data_sector_count: u64,
    pub integrity_offset: u64,
    pub data_offset: u64,
    pub backup_header_offset: u64,
    pub created_at_unix: u64,
    pub expires_at_unix: u64,     // 0 = no Mission TTL expiration
    pub max_failed_attempts: u32, // 0 = auto-shred disabled
    pub failed_attempts: u32,     // live strike counter (excluded from MAC)
    pub key_slots: [KeySlot; MAX_KEY_SLOTS],
    pub header_mac: [u8; TAG_SIZE],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VolumeLayout {
    pub data_sector_count: u64,
    pub integrity_offset: u64,
    pub integrity_bytes: u64,
    pub data_offset: u64,
    pub backup_header_offset: u64,
    pub total_bytes: u64,
    pub detached_header: bool,
}

impl VolumeLayout {
    pub fn from_data_bytes(requested_data_bytes: u64, integrity_enabled: bool) -> Result<Self> {
        Self::compute(requested_data_bytes, integrity_enabled, false)
    }

    pub fn compute(
        requested_data_bytes: u64,
        integrity_enabled: bool,
        detached_header: bool,
    ) -> Result<Self> {
        let sector = SECTOR_SIZE as u64;
        let min_bytes = MIN_DATA_SECTORS * sector;
        if requested_data_bytes < min_bytes {
            return Err(VolumeError::VolumeTooSmall {
                min_bytes,
                requested_bytes: requested_data_bytes,
            });
        }

        let data_sector_count = requested_data_bytes.div_ceil(sector);
        let data_bytes = data_sector_count
            .checked_mul(sector)
            .ok_or(VolumeError::InvalidHeader)?;
        let raw_integrity_bytes = if integrity_enabled {
            data_sector_count
                .checked_mul(TAG_SIZE as u64)
                .ok_or(VolumeError::InvalidHeader)?
        } else {
            0
        };
        let integrity_bytes = raw_integrity_bytes
            .div_ceil(sector)
            .checked_mul(sector)
            .ok_or(VolumeError::InvalidHeader)?;

        if detached_header {
            let integrity_offset = 0u64;
            let data_offset = integrity_bytes;
            let total_bytes = data_offset
                .checked_add(data_bytes)
                .ok_or(VolumeError::InvalidHeader)?;
            Ok(Self {
                data_sector_count,
                integrity_offset,
                integrity_bytes,
                data_offset,
                backup_header_offset: 0,
                total_bytes,
                detached_header: true,
            })
        } else {
            let integrity_offset = HEADER_SIZE as u64;
            let data_offset = integrity_offset
                .checked_add(integrity_bytes)
                .ok_or(VolumeError::InvalidHeader)?;
            let backup_header_offset = data_offset
                .checked_add(data_bytes)
                .ok_or(VolumeError::InvalidHeader)?;
            let total_bytes = backup_header_offset
                .checked_add(HEADER_SIZE as u64)
                .ok_or(VolumeError::InvalidHeader)?;
            Ok(Self {
                data_sector_count,
                integrity_offset,
                integrity_bytes,
                data_offset,
                backup_header_offset,
                total_bytes,
                detached_header: false,
            })
        }
    }
}

impl VolumeHeader {
    pub fn integrity_enabled(&self) -> bool {
        (self.flags & FLAG_INTEGRITY_ENABLED) != 0
    }

    pub fn has_backup_header(&self) -> bool {
        (self.flags & FLAG_HAS_BACKUP_HEADER) != 0
    }

    pub fn is_detached(&self) -> bool {
        (self.flags & FLAG_DETACHED_HEADER) != 0
    }

    pub fn is_hidden(&self) -> bool {
        (self.flags & FLAG_HIDDEN_VOLUME) != 0
    }

    pub fn cipher_mode(&self) -> CipherMode {
        if (self.flags & FLAG_CASCADE_CIPHER) != 0 {
            CipherMode::CascadeAesSerpentXts
        } else {
            CipherMode::Aes256Xts
        }
    }

    pub fn active_slot_count(&self) -> usize {
        self.key_slots.iter().filter(|s| s.active).count()
    }

    #[allow(clippy::too_many_arguments)]
    pub fn build_slot_aad(
        version: u32,
        flags: u32,
        volume_uuid: &[u8; 16],
        slot_index: usize,
        slot_flags: u8,
        kdf_params: &KdfParams,
        salt: &[u8; 32],
        pq_ciphertext: Option<&[u8; PQ_CT_SIZE]>,
    ) -> Vec<u8> {
        let mut aad = Vec::with_capacity(8 + 4 + 4 + 16 + 2 + 12 + 32 + 32);
        aad.extend_from_slice(&HEADER_MAGIC);
        aad.extend_from_slice(&version.to_le_bytes());
        aad.extend_from_slice(&flags.to_le_bytes());
        aad.extend_from_slice(volume_uuid);
        aad.push(slot_index as u8);
        aad.push(slot_flags);
        aad.extend_from_slice(&kdf_params.memory_kib.to_le_bytes());
        aad.extend_from_slice(&kdf_params.iterations.to_le_bytes());
        aad.extend_from_slice(&kdf_params.parallelism.to_le_bytes());
        aad.extend_from_slice(salt);
        if let Some(ct) = pq_ciphertext {
            aad.extend_from_slice(blake3::hash(ct).as_bytes());
        }
        aad
    }

    pub fn serialize_signed(&mut self, header_mac_key: &[u8; 32]) -> [u8; HEADER_SIZE] {
        let mut buf = self.serialize_body();
        let mac_end = if self.version >= 3 {
            HEADER_MAC_INPUT_END
        } else {
            HEADER_MAC_OFFSET
        };
        let mac = compute_header_mac(header_mac_key, &buf[..mac_end]);
        self.header_mac = mac;
        buf[STRIKE_COUNTER_OFFSET..STRIKE_COUNTER_OFFSET + 4]
            .copy_from_slice(&self.failed_attempts.to_le_bytes());
        buf[HEADER_MAC_OFFSET..HEADER_SIZE].copy_from_slice(&mac);
        buf
    }

    fn serialize_body(&self) -> [u8; HEADER_SIZE] {
        let mut buf = [0u8; HEADER_SIZE];
        buf[0..8].copy_from_slice(&HEADER_MAGIC);
        buf[8..12].copy_from_slice(&self.version.to_le_bytes());
        buf[12..16].copy_from_slice(&self.flags.to_le_bytes());
        buf[16..32].copy_from_slice(&self.volume_uuid);
        buf[32..36].copy_from_slice(&self.sector_size.to_le_bytes());
        buf[40..48].copy_from_slice(&self.data_sector_count.to_le_bytes());
        buf[48..56].copy_from_slice(&self.integrity_offset.to_le_bytes());
        buf[56..64].copy_from_slice(&self.data_offset.to_le_bytes());
        buf[64..72].copy_from_slice(&self.backup_header_offset.to_le_bytes());
        buf[72..80].copy_from_slice(&self.created_at_unix.to_le_bytes());
        buf[80..88].copy_from_slice(&self.expires_at_unix.to_le_bytes());
        buf[88..92].copy_from_slice(&self.max_failed_attempts.to_le_bytes());

        for (i, slot) in self.key_slots.iter().enumerate() {
            let start = KEY_SLOTS_OFFSET + i * KEY_SLOT_SIZE;
            let mut slot_buf = [0u8; KEY_SLOT_SIZE];
            slot.serialize(&mut slot_buf);
            buf[start..start + KEY_SLOT_SIZE].copy_from_slice(&slot_buf);

            if let Some(ct) = &slot.pq_ciphertext {
                let pq_start = PQ_SLOTS_OFFSET + i * PQ_CT_SIZE;
                buf[pq_start..pq_start + PQ_CT_SIZE].copy_from_slice(ct.as_slice());
            }
        }

        buf
    }

    pub fn deserialize(raw: &[u8; HEADER_SIZE]) -> Result<Self> {
        if raw[0..8] != HEADER_MAGIC {
            return Err(VolumeError::InvalidHeader);
        }
        let version = u32::from_le_bytes(raw[8..12].try_into().unwrap());
        if !(1..=FORMAT_VERSION).contains(&version) {
            return Err(VolumeError::UnsupportedVersion(version));
        }
        let flags = u32::from_le_bytes(raw[12..16].try_into().unwrap());
        let mut volume_uuid = [0u8; 16];
        volume_uuid.copy_from_slice(&raw[16..32]);

        let sector_size = u32::from_le_bytes(raw[32..36].try_into().unwrap());
        if sector_size != SECTOR_SIZE as u32 {
            return Err(VolumeError::InvalidHeader);
        }

        let data_sector_count = u64::from_le_bytes(raw[40..48].try_into().unwrap());
        let integrity_offset = u64::from_le_bytes(raw[48..56].try_into().unwrap());
        let data_offset = u64::from_le_bytes(raw[56..64].try_into().unwrap());
        let backup_header_offset = u64::from_le_bytes(raw[64..72].try_into().unwrap());
        let created_at_unix = u64::from_le_bytes(raw[72..80].try_into().unwrap());
        let expires_at_unix = u64::from_le_bytes(raw[80..88].try_into().unwrap());
        let max_failed_attempts = u32::from_le_bytes(raw[88..92].try_into().unwrap());
        let failed_attempts = u32::from_le_bytes(
            raw[STRIKE_COUNTER_OFFSET..STRIKE_COUNTER_OFFSET + 4]
                .try_into()
                .unwrap(),
        );

        let detached_or_hidden =
            (flags & FLAG_DETACHED_HEADER) != 0 || (flags & FLAG_HIDDEN_VOLUME) != 0;
        let data_bytes = data_sector_count
            .checked_mul(SECTOR_SIZE as u64)
            .ok_or(VolumeError::InvalidHeader)?;
        let data_end = data_offset
            .checked_add(data_bytes)
            .ok_or(VolumeError::InvalidHeader)?;
        let integrity_enabled = (flags & FLAG_INTEGRITY_ENABLED) != 0;
        if integrity_enabled {
            let tag_bytes = data_sector_count
                .checked_mul(TAG_SIZE as u64)
                .ok_or(VolumeError::InvalidHeader)?;
            let tag_end = integrity_offset
                .checked_add(tag_bytes)
                .ok_or(VolumeError::InvalidHeader)?;
            if tag_end > data_offset {
                return Err(VolumeError::InvalidHeader);
            }
        }
        if (flags & FLAG_HAS_BACKUP_HEADER) != 0 {
            let backup_end = backup_header_offset
                .checked_add(HEADER_SIZE as u64)
                .ok_or(VolumeError::InvalidHeader)?;
            if backup_header_offset < data_end || backup_end < backup_header_offset {
                return Err(VolumeError::InvalidHeader);
            }
        }
        if data_sector_count < MIN_DATA_SECTORS
            || (!detached_or_hidden && data_offset < HEADER_SIZE as u64)
        {
            return Err(VolumeError::InvalidHeader);
        }

        let mut slots = [
            KeySlot::empty(),
            KeySlot::empty(),
            KeySlot::empty(),
            KeySlot::empty(),
        ];
        for (i, slot) in slots.iter_mut().enumerate() {
            let start = KEY_SLOTS_OFFSET + i * KEY_SLOT_SIZE;
            let slot_slice: &[u8; KEY_SLOT_SIZE] =
                raw[start..start + KEY_SLOT_SIZE].try_into().unwrap();
            let pq_start = PQ_SLOTS_OFFSET + i * PQ_CT_SIZE;
            let pq_slice: &[u8; PQ_CT_SIZE] =
                raw[pq_start..pq_start + PQ_CT_SIZE].try_into().unwrap();
            *slot = KeySlot::deserialize(slot_slice, pq_slice)?;
        }

        let mut header_mac = [0u8; TAG_SIZE];
        header_mac.copy_from_slice(&raw[HEADER_MAC_OFFSET..HEADER_SIZE]);

        Ok(Self {
            version,
            flags,
            volume_uuid,
            sector_size,
            data_sector_count,
            integrity_offset,
            data_offset,
            backup_header_offset,
            created_at_unix,
            expires_at_unix,
            max_failed_attempts,
            failed_attempts,
            key_slots: slots,
            header_mac,
        })
    }

    pub fn verify_raw_mac(raw: &[u8; HEADER_SIZE], header_mac_key: &[u8; 32]) -> Result<()> {
        let version = u32::from_le_bytes(raw[8..12].try_into().unwrap());
        let mac_end = if version >= 3 {
            HEADER_MAC_INPUT_END
        } else {
            HEADER_MAC_OFFSET
        };
        let mut expected = [0u8; TAG_SIZE];
        expected.copy_from_slice(&raw[HEADER_MAC_OFFSET..HEADER_SIZE]);
        verify_header_mac(header_mac_key, &raw[..mac_end], &expected)
            .map_err(|_| VolumeError::HeaderTampered)
    }

    pub fn uuid_hex(&self) -> String {
        let u = &self.volume_uuid;
        format!(
            "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            u[0], u[1], u[2], u[3], u[4], u[5], u[6], u[7],
            u[8], u[9], u[10], u[11], u[12], u[13], u[14], u[15]
        )
    }
}
