use crate::device::BlockDevice;
use crate::error::{Result, VolumeError};
use crate::header::{
    KeySlot, VolumeHeader, VolumeLayout, FLAG_CASCADE_CIPHER, FLAG_DETACHED_HEADER,
    FLAG_HAS_BACKUP_HEADER, FLAG_HIDDEN_VOLUME, FLAG_INTEGRITY_ENABLED, FORMAT_VERSION,
    HEADER_SIZE, MAX_KEY_SLOTS, MIN_DATA_SECTORS, SLOT_FLAG_PQ_HYBRID, SLOT_FLAG_REQUIRES_KEYFILE,
    STRIKE_COUNTER_OFFSET,
};
use falcon_crypto::{
    apply_hidden_header_mask, build_duress_payload, combine_hybrid_kek, compute_sector_tag,
    derive_kek, is_duress_payload, pq_decapsulate, pq_encapsulate, random_bytes,
    unwrap_master_secret, verify_sector_tag, wrap_master_secret, CipherMode, KdfParams, KdfProfile,
    PqKeypair, SecureArray, VolumeKeys, XtsCipher, MASTER_SECRET_SIZE, SECTOR_SIZE, TAG_SIZE,
    WRAP_NONCE_SIZE,
};
use rand::rngs::OsRng;
use rand::RngCore;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

#[derive(Debug, Clone)]
pub struct CreateOptions {
    pub data_bytes: u64,
    pub kdf_params: KdfParams,
    pub integrity_enabled: bool,
    pub cipher_mode: CipherMode,
    pub detached_header_path: Option<PathBuf>,
    pub expires_at_unix: u64,
    pub max_failed_attempts: u32,
    pub label: String,
}

pub struct AuthMaterial<'a> {
    pub passphrase: &'a [u8],
    pub keyfile_hash: Option<&'a [u8; 32]>,
    pub pq_keypair: Option<&'a PqKeypair>,
}

impl<'a> AuthMaterial<'a> {
    pub fn password_only(passphrase: &'a [u8]) -> Self {
        Self {
            passphrase,
            keyfile_hash: None,
            pq_keypair: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct VerifyReport {
    pub total_sectors: u64,
    pub verified_sectors: u64,
    pub corrupted_sectors: Vec<u64>,
    pub primary_header_ok: bool,
    pub backup_header_ok: bool,
    pub headers_identical: bool,
    pub detached_header: bool,
    pub hidden_volume: bool,
}

impl VerifyReport {
    pub fn is_clean(&self) -> bool {
        if self.detached_header || self.hidden_volume {
            self.primary_header_ok && self.corrupted_sectors.is_empty()
        } else {
            self.primary_header_ok
                && self.backup_header_ok
                && self.headers_identical
                && self.corrupted_sectors.is_empty()
        }
    }
}

enum UnlockOutcome {
    Unlocked(Box<VolumeHeader>, VolumeKeys, usize),
    DuressTriggered,
}

struct HiddenHeaderBinding {
    base_offset: u64,
    mask_salt: [u8; 32],
    mask_key: SecureArray<32>,
}

pub struct Volume<D: BlockDevice> {
    device: D,
    header: VolumeHeader,
    keys: VolumeKeys,
    xts: XtsCipher,
    unlocked_slot: usize,
    recovered_from_backup: bool,
    detached_header_path: Option<PathBuf>,
    hidden_binding: Option<HiddenHeaderBinding>,
}

impl<D: BlockDevice> Volume<D> {
    pub fn create<F>(
        mut device: D,
        opts: &CreateOptions,
        auth: &AuthMaterial<'_>,
        mut on_progress: F,
    ) -> Result<Self>
    where
        F: FnMut(u64, u64),
    {
        opts.kdf_params.validate()?;
        let detached = opts.detached_header_path.is_some();
        let layout = VolumeLayout::compute(opts.data_bytes, opts.integrity_enabled, detached)?;
        device.set_len(layout.total_bytes)?;

        let volume_uuid = random_bytes::<16>();
        let keys = VolumeKeys::generate(&volume_uuid)?;
        let xts = keys.cipher(opts.cipher_mode)?;

        let mut flags = 0u32;
        if opts.integrity_enabled {
            flags |= FLAG_INTEGRITY_ENABLED;
        }
        if !detached {
            flags |= FLAG_HAS_BACKUP_HEADER;
        } else {
            flags |= FLAG_DETACHED_HEADER;
        }
        if opts.cipher_mode == CipherMode::CascadeAesSerpentXts {
            flags |= FLAG_CASCADE_CIPHER;
        }

        let slot0 = build_wrapped_slot(
            FORMAT_VERSION,
            flags,
            &volume_uuid,
            0,
            auth,
            &opts.kdf_params,
            &opts.label,
            keys.master_secret(),
        )?;

        let created_at_unix = unix_now();

        let mut header = VolumeHeader {
            version: FORMAT_VERSION,
            flags,
            volume_uuid,
            sector_size: SECTOR_SIZE as u32,
            data_sector_count: layout.data_sector_count,
            integrity_offset: layout.integrity_offset,
            data_offset: layout.data_offset,
            backup_header_offset: layout.backup_header_offset,
            created_at_unix,
            expires_at_unix: opts.expires_at_unix,
            max_failed_attempts: opts.max_failed_attempts,
            failed_attempts: 0,
            key_slots: [slot0, KeySlot::empty(), KeySlot::empty(), KeySlot::empty()],
            header_mac: [0u8; TAG_SIZE],
        };

        init_encrypted_sectors(
            &mut device,
            &xts,
            &keys,
            &volume_uuid,
            layout.data_offset,
            layout.integrity_offset,
            layout.data_sector_count,
            opts.integrity_enabled,
            &mut on_progress,
        )?;

        let signed_raw = header.serialize_signed(keys.header_mac_key());
        if let Some(ref hdr_path) = opts.detached_header_path {
            write_detached_header(hdr_path, &signed_raw)?;
        } else {
            device.write_all_at(0, &signed_raw)?;
            device.write_all_at(layout.backup_header_offset, &signed_raw)?;
        }
        device.sync_all()?;

        Ok(Self {
            device,
            header,
            keys,
            xts,
            unlocked_slot: 0,
            recovered_from_backup: false,
            detached_header_path: opts.detached_header_path.clone(),
            hidden_binding: None,
        })
    }

    /// Creates a Plausible Deniability Hidden Volume inside the upper half of this unlocked
    /// Outer Volume's data space. Zero `FLCNDSK1` magic bytes appear on disk (header is
    /// BLAKE3-XOF obfuscated), and the outer volume's BLAKE3 sector MACs are updated so even
    /// `falcon verify` on the outer decoy volume continues to pass cleanly.
    pub fn create_hidden_in_outer(
        &mut self,
        hidden_auth: &AuthMaterial<'_>,
        kdf_params: &KdfParams,
        cipher_mode: CipherMode,
        label: &str,
    ) -> Result<(u64, u64)> {
        if self.header.is_hidden() {
            return Err(VolumeError::HiddenVolume(
                "cannot nest a hidden volume inside another hidden volume".into(),
            ));
        }
        kdf_params.validate()?;

        let outer_sectors = self.header.data_sector_count;
        if outer_sectors < 256 {
            return Err(VolumeError::HiddenVolume(
                "outer volume must have at least 256 sectors (1 MiB) to host a hidden volume"
                    .into(),
            ));
        }

        let start_sector = outer_sectors / 2;
        let region_sectors = outer_sectors - start_sector;
        let hidden_base = self.header.data_offset + start_sector * (SECTOR_SIZE as u64);

        // 1 salt sector + 4 obfuscated header sectors = 5 sectors header overhead
        let header_overhead = 5u64;
        let usable_pool = region_sectors.saturating_sub(header_overhead);
        // Reserve 1 tag sector per 128 data sectors (4096 / 32 = 128)
        let data_sectors = (usable_pool * 128) / 129;
        if data_sectors < MIN_DATA_SECTORS {
            return Err(VolumeError::HiddenVolume(
                "insufficient free upper-half space for hidden volume".into(),
            ));
        }
        let integrity_sectors = data_sectors.div_ceil(128);
        let integrity_offset = hidden_base + header_overhead * (SECTOR_SIZE as u64);
        let data_offset = integrity_offset + integrity_sectors * (SECTOR_SIZE as u64);

        let volume_uuid = random_bytes::<16>();
        let keys = VolumeKeys::generate(&volume_uuid)?;
        let xts = keys.cipher(cipher_mode)?;

        let mut flags = FLAG_INTEGRITY_ENABLED | FLAG_HIDDEN_VOLUME;
        if cipher_mode == CipherMode::CascadeAesSerpentXts {
            flags |= FLAG_CASCADE_CIPHER;
        }

        let slot0 = build_wrapped_slot(
            FORMAT_VERSION,
            flags,
            &volume_uuid,
            0,
            hidden_auth,
            kdf_params,
            label,
            keys.master_secret(),
        )?;

        let mut header = VolumeHeader {
            version: FORMAT_VERSION,
            flags,
            volume_uuid,
            sector_size: SECTOR_SIZE as u32,
            data_sector_count: data_sectors,
            integrity_offset,
            data_offset,
            backup_header_offset: 0,
            created_at_unix: unix_now(),
            expires_at_unix: 0,
            max_failed_attempts: 0,
            failed_attempts: 0,
            key_slots: [slot0, KeySlot::empty(), KeySlot::empty(), KeySlot::empty()],
            header_mac: [0u8; TAG_SIZE],
        };

        // Write salt sector (random salt + CSPRNG padding) + XOF-obfuscated 16 KiB header
        let mut salt_sector = [0u8; SECTOR_SIZE];
        OsRng.fill_bytes(&mut salt_sector);
        let mut mask_salt = [0u8; 32];
        mask_salt.copy_from_slice(&salt_sector[..32]);
        let mask_key = derive_kek(
            hidden_auth.passphrase,
            hidden_auth.keyfile_hash,
            &mask_salt,
            &KdfProfile::FastTest.params(),
        )?;

        let mut masked_hdr = header.serialize_signed(keys.header_mac_key());
        apply_hidden_header_mask(&mask_key, &mask_salt, &mut masked_hdr);

        self.device.write_all_at(hidden_base, &salt_sector)?;
        self.device
            .write_all_at(hidden_base + SECTOR_SIZE as u64, &masked_hdr)?;

        // Initialize hidden volume data sectors & integrity tags
        init_encrypted_sectors(
            &mut self.device,
            &xts,
            &keys,
            &volume_uuid,
            data_offset,
            integrity_offset,
            data_sectors,
            true,
            &mut |_, _| {},
        )?;

        self.refresh_upper_half_macs()?;
        Ok((start_sector, data_sectors))
    }

    /// Recomputes outer BLAKE3 sector MACs for the upper half `[N/2 .. N)` so an outer decoy
    /// volume passes full integrity verification after a hidden volume is formatted inside it.
    pub fn refresh_upper_half_macs(&mut self) -> Result<()> {
        if !self.header.integrity_enabled() {
            return Ok(());
        }
        let outer_sectors = self.header.data_sector_count;
        let start_sector = outer_sectors / 2;
        let mut buf = [0u8; SECTOR_SIZE];
        for s_idx in start_sector..outer_sectors {
            let off = self.header.data_offset + s_idx * (SECTOR_SIZE as u64);
            self.device.read_exact_at(off, &mut buf)?;
            let tag = compute_sector_tag(
                self.keys.sector_mac_key(),
                &self.header.volume_uuid,
                s_idx,
                &buf,
            );
            let tag_off = self.header.integrity_offset + s_idx * (TAG_SIZE as u64);
            self.device.write_all_at(tag_off, &tag)?;
        }
        buf.zeroize();
        self.device.sync_all()?;
        Ok(())
    }

    /// Opens a Plausible Deniability Hidden Volume residing in the upper half of an outer container.
    pub fn open_hidden(
        mut device: D,
        hidden_auth: &AuthMaterial<'_>,
        outer_detached_header: Option<&Path>,
    ) -> Result<Self> {
        let (outer_hdr, _) = Self::inspect_header(&mut device, outer_detached_header)?;
        let start_sector = outer_hdr.data_sector_count / 2;
        let hidden_base = outer_hdr.data_offset + start_sector * (SECTOR_SIZE as u64);

        let mut mask_salt = [0u8; 32];
        device.read_exact_at(hidden_base, &mut mask_salt)?;

        let mask_key = derive_kek(
            hidden_auth.passphrase,
            hidden_auth.keyfile_hash,
            &mask_salt,
            &KdfProfile::FastTest.params(),
        )?;

        let mut raw_hdr = [0u8; HEADER_SIZE];
        device.read_exact_at(hidden_base + SECTOR_SIZE as u64, &mut raw_hdr)?;
        apply_hidden_header_mask(&mask_key, &mask_salt, &mut raw_hdr);

        match try_unlock_raw_header(&raw_hdr, hidden_auth)? {
            UnlockOutcome::DuressTriggered => {
                // Wipe hidden header block on duress
                let mut wipe = [0u8; HEADER_SIZE];
                for _ in 0..3 {
                    OsRng.fill_bytes(&mut wipe);
                    let _ = device.write_all_at(hidden_base + SECTOR_SIZE as u64, &wipe);
                    let _ = device.sync_all();
                }
                Err(VolumeError::AuthenticationFailed)
            }
            UnlockOutcome::Unlocked(header, keys, slot_idx) => {
                check_expiry(&header)?;
                let xts = keys.cipher(header.cipher_mode())?;
                Ok(Self {
                    device,
                    header: *header,
                    keys,
                    xts,
                    unlocked_slot: slot_idx,
                    recovered_from_backup: false,
                    detached_header_path: None,
                    hidden_binding: Some(HiddenHeaderBinding {
                        base_offset: hidden_base,
                        mask_salt,
                        mask_key,
                    }),
                })
            }
        }
    }

    pub fn inspect_header(
        device: &mut D,
        detached_header: Option<&Path>,
    ) -> Result<(VolumeHeader, bool)> {
        if let Some(p) = detached_header {
            let raw = read_detached_header(p)?;
            return Ok((VolumeHeader::deserialize(&raw)?, false));
        }

        let mut raw = [0u8; HEADER_SIZE];
        if device.read_exact_at(0, &mut raw).is_ok() {
            if let Ok(hdr) = VolumeHeader::deserialize(&raw) {
                return Ok((hdr, false));
            }
        }

        let total = device.total_size()?;
        if total >= (HEADER_SIZE as u64) * 2 {
            device.read_exact_at(total - HEADER_SIZE as u64, &mut raw)?;
            let hdr = VolumeHeader::deserialize(&raw)?;
            return Ok((hdr, true));
        }

        Err(VolumeError::InvalidHeader)
    }

    pub fn open(
        mut device: D,
        auth: &AuthMaterial<'_>,
        detached_header: Option<&Path>,
    ) -> Result<Self> {
        if let Some(hdr_path) = detached_header {
            let raw = read_detached_header(hdr_path)?;
            let parsed_meta = VolumeHeader::deserialize(&raw)?;
            check_expiry(&parsed_meta)?;

            match try_unlock_raw_header(&raw, auth) {
                Ok(UnlockOutcome::DuressTriggered) => {
                    let _ = Self::crypto_shred(&mut device, Some(hdr_path));
                    return Err(VolumeError::AuthenticationFailed);
                }
                Ok(UnlockOutcome::Unlocked(mut header, keys, slot_idx)) => {
                    let xts = keys.cipher(header.cipher_mode())?;
                    if header.failed_attempts > 0 {
                        header.failed_attempts = 0;
                        let mut vol = Self {
                            device,
                            header: *header,
                            keys,
                            xts,
                            unlocked_slot: slot_idx,
                            recovered_from_backup: false,
                            detached_header_path: Some(hdr_path.to_path_buf()),
                            hidden_binding: None,
                        };
                        let _ = vol.persist_headers();
                        return Ok(vol);
                    }
                    return Ok(Self {
                        device,
                        header: *header,
                        keys,
                        xts,
                        unlocked_slot: slot_idx,
                        recovered_from_backup: false,
                        detached_header_path: Some(hdr_path.to_path_buf()),
                        hidden_binding: None,
                    });
                }
                Err(VolumeError::AuthenticationFailed) => {
                    return Err(record_strike_and_maybe_shred(
                        &mut device,
                        Some(hdr_path),
                        &parsed_meta,
                    ));
                }
                Err(e) => return Err(e),
            }
        }

        let mut raw_primary = [0u8; HEADER_SIZE];
        let primary_meta = device
            .read_exact_at(0, &mut raw_primary)
            .and_then(|_| VolumeHeader::deserialize(&raw_primary));

        if let Ok(ref meta) = primary_meta {
            check_expiry(meta)?;
        }

        let primary_attempt = primary_meta
            .as_ref()
            .map(|_| ())
            .map_err(|_| VolumeError::InvalidHeader)
            .and_then(|_| try_unlock_raw_header(&raw_primary, auth));

        match primary_attempt {
            Ok(UnlockOutcome::DuressTriggered) => {
                let _ = Self::crypto_shred(&mut device, None);
                Err(VolumeError::AuthenticationFailed)
            }
            Ok(UnlockOutcome::Unlocked(mut header, keys, slot_idx)) => {
                let xts = keys.cipher(header.cipher_mode())?;
                let had_strikes = header.failed_attempts > 0;
                header.failed_attempts = 0;
                let mut vol = Self {
                    device,
                    header: *header,
                    keys,
                    xts,
                    unlocked_slot: slot_idx,
                    recovered_from_backup: false,
                    detached_header_path: None,
                    hidden_binding: None,
                };
                if had_strikes {
                    let _ = vol.persist_headers();
                }
                Ok(vol)
            }
            Err(VolumeError::AuthenticationFailed) => {
                if let Ok(ref meta) = primary_meta {
                    return Err(record_strike_and_maybe_shred(&mut device, None, meta));
                }
                Err(VolumeError::AuthenticationFailed)
            }
            Err(primary_err) => {
                let should_try_backup = matches!(
                    primary_err,
                    VolumeError::InvalidHeader | VolumeError::HeaderTampered
                );
                if should_try_backup {
                    let total = device.total_size()?;
                    if total >= (HEADER_SIZE as u64) * 2 {
                        let mut raw_backup = [0u8; HEADER_SIZE];
                        if device
                            .read_exact_at(total - HEADER_SIZE as u64, &mut raw_backup)
                            .is_ok()
                        {
                            if let Ok(backup_meta) = VolumeHeader::deserialize(&raw_backup) {
                                check_expiry(&backup_meta)?;
                            }
                            match try_unlock_raw_header(&raw_backup, auth) {
                                Ok(UnlockOutcome::DuressTriggered) => {
                                    let _ = Self::crypto_shred(&mut device, None);
                                    return Err(VolumeError::AuthenticationFailed);
                                }
                                Ok(UnlockOutcome::Unlocked(header, keys, slot_idx)) => {
                                    let xts = keys.cipher(header.cipher_mode())?;
                                    return Ok(Self {
                                        device,
                                        header: *header,
                                        keys,
                                        xts,
                                        unlocked_slot: slot_idx,
                                        recovered_from_backup: true,
                                        detached_header_path: None,
                                        hidden_binding: None,
                                    });
                                }
                                Err(_) => {}
                            }
                        }
                    }
                }
                Err(primary_err)
            }
        }
    }

    pub fn header(&self) -> &VolumeHeader {
        &self.header
    }

    pub fn unlocked_slot(&self) -> usize {
        self.unlocked_slot
    }

    pub fn recovered_from_backup(&self) -> bool {
        self.recovered_from_backup
    }

    pub fn detached_header_path(&self) -> Option<&Path> {
        self.detached_header_path.as_deref()
    }

    pub fn is_hidden(&self) -> bool {
        self.hidden_binding.is_some()
    }

    pub fn sector_count(&self) -> u64 {
        self.header.data_sector_count
    }

    pub fn custody_signing_key(&self) -> ed25519_dalek::SigningKey {
        self.keys.custody_signing_key()
    }

    pub fn custody_verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        self.keys.custody_verifying_key()
    }

    pub fn custody_pubkey_hex(&self) -> String {
        hex::encode(self.keys.custody_verifying_key().as_bytes())
    }

    pub fn sync_all(&mut self) -> Result<()> {
        self.device.sync_all()
    }

    pub fn read_sector(&mut self, sector_index: u64, out: &mut [u8; SECTOR_SIZE]) -> Result<()> {
        if sector_index >= self.header.data_sector_count {
            return Err(VolumeError::SectorOutOfBounds {
                sector: sector_index,
                total: self.header.data_sector_count,
            });
        }

        let data_off = self.header.data_offset + sector_index * (SECTOR_SIZE as u64);
        self.device.read_exact_at(data_off, out)?;

        if self.header.integrity_enabled() {
            let tag_off = self.header.integrity_offset + sector_index * (TAG_SIZE as u64);
            let mut expected_tag = [0u8; TAG_SIZE];
            self.device.read_exact_at(tag_off, &mut expected_tag)?;

            if verify_sector_tag(
                self.keys.sector_mac_key(),
                &self.header.volume_uuid,
                sector_index,
                out,
                &expected_tag,
            )
            .is_err()
            {
                out.zeroize();
                return Err(VolumeError::TamperDetected {
                    sector: sector_index,
                });
            }
        }

        self.xts.decrypt_sector(sector_index, out)?;
        Ok(())
    }

    pub fn write_sector(&mut self, sector_index: u64, plaintext: &[u8; SECTOR_SIZE]) -> Result<()> {
        if sector_index >= self.header.data_sector_count {
            return Err(VolumeError::SectorOutOfBounds {
                sector: sector_index,
                total: self.header.data_sector_count,
            });
        }

        let mut ct = *plaintext;
        self.xts.encrypt_sector(sector_index, &mut ct)?;

        let data_off = self.header.data_offset + sector_index * (SECTOR_SIZE as u64);
        self.device.write_all_at(data_off, &ct)?;

        if self.header.integrity_enabled() {
            let tag = compute_sector_tag(
                self.keys.sector_mac_key(),
                &self.header.volume_uuid,
                sector_index,
                &ct,
            );
            let tag_off = self.header.integrity_offset + sector_index * (TAG_SIZE as u64);
            self.device.write_all_at(tag_off, &tag)?;
        }

        ct.zeroize();
        Ok(())
    }

    pub fn erase_sector(&mut self, sector_index: u64) -> Result<()> {
        let mut noise = [0u8; SECTOR_SIZE];
        OsRng.fill_bytes(&mut noise);
        let res = self.write_sector(sector_index, &noise);
        noise.zeroize();
        res
    }

    pub fn verify_all_sectors<F>(&mut self, mut on_progress: F) -> Result<VerifyReport>
    where
        F: FnMut(u64, u64),
    {
        let detached = self.detached_header_path.is_some();
        let hidden = self.hidden_binding.is_some();

        let (primary_header_ok, backup_header_ok, headers_identical) = if let Some(ref hb) =
            self.hidden_binding
        {
            let mut raw = [0u8; HEADER_SIZE];
            let ok = self
                .device
                .read_exact_at(hb.base_offset + SECTOR_SIZE as u64, &mut raw)
                .is_ok()
                && {
                    apply_hidden_header_mask(&hb.mask_key, &hb.mask_salt, &mut raw);
                    VolumeHeader::verify_raw_mac(&raw, self.keys.header_mac_key()).is_ok()
                };
            (ok, true, true)
        } else if let Some(ref hdr_path) = self.detached_header_path {
            let ok = read_detached_header(hdr_path)
                .and_then(|raw| VolumeHeader::verify_raw_mac(&raw, self.keys.header_mac_key()))
                .is_ok();
            (ok, true, true)
        } else {
            let mut raw_primary = [0u8; HEADER_SIZE];
            let mut raw_backup = [0u8; HEADER_SIZE];

            let p_ok = self.device.read_exact_at(0, &mut raw_primary).is_ok()
                && VolumeHeader::verify_raw_mac(&raw_primary, self.keys.header_mac_key()).is_ok();

            let b_ok = self
                .device
                .read_exact_at(self.header.backup_header_offset, &mut raw_backup)
                .is_ok()
                && VolumeHeader::verify_raw_mac(&raw_backup, self.keys.header_mac_key()).is_ok();

            let same = bool::from(raw_primary.ct_eq(&raw_backup));
            (p_ok, b_ok, same)
        };

        let total = self.header.data_sector_count;
        let mut corrupted = Vec::new();
        let mut verified = 0u64;

        if self.header.integrity_enabled() {
            let mut ct_buf = [0u8; SECTOR_SIZE];
            let mut tag_buf = [0u8; TAG_SIZE];

            for s_idx in 0..total {
                let data_off = self.header.data_offset + s_idx * (SECTOR_SIZE as u64);
                let tag_off = self.header.integrity_offset + s_idx * (TAG_SIZE as u64);
                self.device.read_exact_at(data_off, &mut ct_buf)?;
                self.device.read_exact_at(tag_off, &mut tag_buf)?;

                if verify_sector_tag(
                    self.keys.sector_mac_key(),
                    &self.header.volume_uuid,
                    s_idx,
                    &ct_buf,
                    &tag_buf,
                )
                .is_ok()
                {
                    verified += 1;
                } else {
                    corrupted.push(s_idx);
                }
                on_progress(s_idx + 1, total);
            }
        } else {
            verified = total;
            on_progress(total, total);
        }

        Ok(VerifyReport {
            total_sectors: total,
            verified_sectors: verified,
            corrupted_sectors: corrupted,
            primary_header_ok,
            backup_header_ok,
            headers_identical,
            detached_header: detached,
            hidden_volume: hidden,
        })
    }

    pub fn add_keyslot(
        &mut self,
        preferred_slot: Option<usize>,
        auth: &AuthMaterial<'_>,
        kdf_params: &KdfParams,
        label: &str,
    ) -> Result<usize> {
        let slot_idx = self.pick_free_slot(preferred_slot)?;
        let slot = build_wrapped_slot(
            self.header.version,
            self.header.flags,
            &self.header.volume_uuid,
            slot_idx,
            auth,
            kdf_params,
            label,
            self.keys.master_secret(),
        )?;

        self.header.key_slots[slot_idx] = slot;
        self.persist_headers()?;
        Ok(slot_idx)
    }

    pub fn add_duress_slot(
        &mut self,
        preferred_slot: Option<usize>,
        auth: &AuthMaterial<'_>,
        kdf_params: &KdfParams,
        decoy_label: &str,
    ) -> Result<usize> {
        let slot_idx = self.pick_free_slot(preferred_slot)?;
        let duress_payload = build_duress_payload(&self.header.volume_uuid);
        let slot = build_wrapped_slot(
            self.header.version,
            self.header.flags,
            &self.header.volume_uuid,
            slot_idx,
            auth,
            kdf_params,
            decoy_label,
            &duress_payload,
        )?;

        self.header.key_slots[slot_idx] = slot;
        self.persist_headers()?;
        Ok(slot_idx)
    }

    pub fn set_policy(&mut self, expires_at_unix: u64, max_failed_attempts: u32) -> Result<()> {
        self.header.expires_at_unix = expires_at_unix;
        self.header.max_failed_attempts = max_failed_attempts;
        self.header.failed_attempts = 0;
        self.persist_headers()
    }

    fn pick_free_slot(&self, preferred: Option<usize>) -> Result<usize> {
        match preferred {
            Some(idx) => {
                if idx >= MAX_KEY_SLOTS {
                    return Err(VolumeError::InvalidKeySlot(idx));
                }
                if self.header.key_slots[idx].active {
                    return Err(VolumeError::KeySlotOccupied(idx));
                }
                Ok(idx)
            }
            None => self
                .header
                .key_slots
                .iter()
                .position(|s| !s.active)
                .ok_or(VolumeError::NoFreeKeySlot),
        }
    }

    pub fn change_slot_passphrase(
        &mut self,
        slot_idx: usize,
        auth: &AuthMaterial<'_>,
        new_kdf_params: Option<&KdfParams>,
    ) -> Result<()> {
        if slot_idx >= MAX_KEY_SLOTS {
            return Err(VolumeError::InvalidKeySlot(slot_idx));
        }
        if !self.header.key_slots[slot_idx].active {
            return Err(VolumeError::KeySlotEmpty(slot_idx));
        }

        let kdf_params = new_kdf_params
            .copied()
            .unwrap_or(self.header.key_slots[slot_idx].kdf_params);
        let label = self.header.key_slots[slot_idx].label.clone();

        let slot = build_wrapped_slot(
            self.header.version,
            self.header.flags,
            &self.header.volume_uuid,
            slot_idx,
            auth,
            &kdf_params,
            &label,
            self.keys.master_secret(),
        )?;

        self.header.key_slots[slot_idx] = slot;
        self.persist_headers()
    }

    pub fn remove_keyslot(&mut self, slot_idx: usize) -> Result<()> {
        if slot_idx >= MAX_KEY_SLOTS {
            return Err(VolumeError::InvalidKeySlot(slot_idx));
        }
        if !self.header.key_slots[slot_idx].active {
            return Err(VolumeError::KeySlotEmpty(slot_idx));
        }
        if self.header.active_slot_count() <= 1 {
            return Err(VolumeError::LastKeySlot);
        }

        self.header.key_slots[slot_idx] = KeySlot::empty();
        self.persist_headers()
    }

    pub fn persist_headers(&mut self) -> Result<()> {
        let mut signed_raw = self.header.serialize_signed(self.keys.header_mac_key());
        if let Some(ref hb) = self.hidden_binding {
            apply_hidden_header_mask(&hb.mask_key, &hb.mask_salt, &mut signed_raw);
            self.device
                .write_all_at(hb.base_offset + SECTOR_SIZE as u64, &signed_raw)?;
            self.device.sync_all()?;
        } else if let Some(ref hdr_path) = self.detached_header_path {
            write_detached_header(hdr_path, &signed_raw)?;
        } else {
            self.device.write_all_at(0, &signed_raw)?;
            self.device
                .write_all_at(self.header.backup_header_offset, &signed_raw)?;
            self.device.sync_all()?;
        }
        Ok(())
    }

    pub fn export_header(
        device: &mut D,
        detached_header: Option<&Path>,
    ) -> Result<[u8; HEADER_SIZE]> {
        if let Some(p) = detached_header {
            let raw = read_detached_header(p)?;
            let _ = VolumeHeader::deserialize(&raw)?;
            return Ok(raw);
        }
        let mut raw = [0u8; HEADER_SIZE];
        device.read_exact_at(0, &mut raw)?;
        let _ = VolumeHeader::deserialize(&raw)?;
        Ok(raw)
    }

    pub fn restore_header(
        device: &mut D,
        raw_header: &[u8],
        detached_header: Option<&Path>,
    ) -> Result<()> {
        if raw_header.len() != HEADER_SIZE {
            return Err(VolumeError::InvalidBackupHeaderSize {
                expected: HEADER_SIZE,
                actual: raw_header.len(),
            });
        }
        let arr: &[u8; HEADER_SIZE] = raw_header.try_into().unwrap();
        let hdr = VolumeHeader::deserialize(arr)?;
        if let Some(p) = detached_header {
            write_detached_header(p, arr)?;
        } else {
            device.write_all_at(0, arr)?;
            if !hdr.is_detached() {
                device.write_all_at(hdr.backup_header_offset, arr)?;
            }
            device.sync_all()?;
        }
        Ok(())
    }

    pub fn crypto_shred(device: &mut D, detached_header: Option<&Path>) -> Result<()> {
        let mut wipe = [0u8; HEADER_SIZE];

        if let Some(hdr_path) = detached_header {
            if let Ok(mut f) = OpenOptions::new().write(true).open(hdr_path) {
                for _ in 0..3 {
                    OsRng.fill_bytes(&mut wipe);
                    let _ = f.seek(SeekFrom::Start(0));
                    let _ = f.write_all(&wipe);
                    let _ = f.sync_all();
                }
            }
        }

        let total = device.total_size()?;
        let backup_offset = Self::inspect_header(device, None)
            .map(|(h, _)| h.backup_header_offset)
            .unwrap_or_else(|_| total.saturating_sub(HEADER_SIZE as u64));

        for _ in 0..3 {
            OsRng.fill_bytes(&mut wipe);
            if total >= HEADER_SIZE as u64 {
                device.write_all_at(0, &wipe)?;
            }
            if backup_offset >= HEADER_SIZE as u64 && backup_offset + (HEADER_SIZE as u64) <= total
            {
                OsRng.fill_bytes(&mut wipe);
                device.write_all_at(backup_offset, &wipe)?;
            }
            device.sync_all()?;
        }
        wipe.zeroize();
        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
fn init_encrypted_sectors<D: BlockDevice, F: FnMut(u64, u64)>(
    device: &mut D,
    xts: &XtsCipher,
    keys: &VolumeKeys,
    volume_uuid: &[u8; 16],
    data_offset: u64,
    integrity_offset: u64,
    total: u64,
    integrity_enabled: bool,
    on_progress: &mut F,
) -> Result<()> {
    const BATCH_SECTORS: usize = 256;
    let mut data_batch = vec![0u8; BATCH_SECTORS * SECTOR_SIZE];
    let mut tag_batch = vec![0u8; BATCH_SECTORS * TAG_SIZE];
    let mut sector_idx: u64 = 0;

    while sector_idx < total {
        let count = ((total - sector_idx) as usize).min(BATCH_SECTORS);
        let data_slice = &mut data_batch[..count * SECTOR_SIZE];
        data_slice.fill(0);

        for i in 0..count {
            let s_idx = sector_idx + i as u64;
            let sec = &mut data_slice[i * SECTOR_SIZE..(i + 1) * SECTOR_SIZE];
            xts.encrypt_sector(s_idx, sec)?;
            if integrity_enabled {
                let tag = compute_sector_tag(keys.sector_mac_key(), volume_uuid, s_idx, sec);
                tag_batch[i * TAG_SIZE..(i + 1) * TAG_SIZE].copy_from_slice(&tag);
            }
        }

        let data_off = data_offset + sector_idx * (SECTOR_SIZE as u64);
        device.write_all_at(data_off, data_slice)?;
        if integrity_enabled {
            let tag_off = integrity_offset + sector_idx * (TAG_SIZE as u64);
            device.write_all_at(tag_off, &tag_batch[..count * TAG_SIZE])?;
        }
        sector_idx += count as u64;
        on_progress(sector_idx, total);
    }
    Ok(())
}

fn check_expiry(header: &VolumeHeader) -> Result<()> {
    if header.expires_at_unix != 0 && unix_now() > header.expires_at_unix {
        return Err(VolumeError::VolumeExpired {
            expires_at_unix: header.expires_at_unix,
        });
    }
    Ok(())
}

fn record_strike_and_maybe_shred<D: BlockDevice>(
    device: &mut D,
    detached_header: Option<&Path>,
    meta: &VolumeHeader,
) -> VolumeError {
    if meta.max_failed_attempts == 0 {
        return VolumeError::AuthenticationFailed;
    }
    let next_strikes = meta.failed_attempts.saturating_add(1);
    if next_strikes >= meta.max_failed_attempts {
        let _ = Volume::crypto_shred(device, detached_header);
        return VolumeError::AutoShredded;
    }

    let strike_bytes = next_strikes.to_le_bytes();
    if let Some(hdr_path) = detached_header {
        if let Ok(mut f) = OpenOptions::new().read(true).write(true).open(hdr_path) {
            let _ = f.seek(SeekFrom::Start(STRIKE_COUNTER_OFFSET as u64));
            let _ = f.write_all(&strike_bytes);
            let _ = f.sync_all();
        }
    } else {
        let _ = device.write_all_at(STRIKE_COUNTER_OFFSET as u64, &strike_bytes);
        if meta.has_backup_header() {
            let _ = device.write_all_at(
                meta.backup_header_offset + STRIKE_COUNTER_OFFSET as u64,
                &strike_bytes,
            );
        }
        let _ = device.sync_all();
    }

    VolumeError::AuthenticationFailed
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn read_detached_header(path: &Path) -> Result<[u8; HEADER_SIZE]> {
    let mut f = File::open(path)?;
    let mut buf = [0u8; HEADER_SIZE];
    f.read_exact(&mut buf)?;
    Ok(buf)
}

fn write_detached_header(path: &Path, raw: &[u8; HEADER_SIZE]) -> Result<()> {
    let mut f = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = f.set_permissions(std::fs::Permissions::from_mode(0o600));
    }
    f.write_all(raw)?;
    f.sync_all()?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn build_wrapped_slot(
    version: u32,
    flags: u32,
    volume_uuid: &[u8; 16],
    slot_idx: usize,
    auth: &AuthMaterial<'_>,
    kdf_params: &KdfParams,
    label: &str,
    payload: &SecureArray<MASTER_SECRET_SIZE>,
) -> Result<KeySlot> {
    let salt = random_bytes::<32>();
    let nonce = random_bytes::<WRAP_NONCE_SIZE>();
    let classical_kek = derive_kek(auth.passphrase, auth.keyfile_hash, &salt, kdf_params)?;

    let (effective_kek, pq_ciphertext) = if let Some(kp) = auth.pq_keypair {
        let (ct, pq_ss) = pq_encapsulate(&kp.ek)?;
        let hybrid = combine_hybrid_kek(&classical_kek, &pq_ss, &salt)?;
        (hybrid, Some(Box::new(ct)))
    } else {
        (classical_kek, None)
    };

    let mut slot_flags = 0u8;
    if auth.keyfile_hash.is_some() {
        slot_flags |= SLOT_FLAG_REQUIRES_KEYFILE;
    }
    if pq_ciphertext.is_some() {
        slot_flags |= SLOT_FLAG_PQ_HYBRID;
    }

    let aad = VolumeHeader::build_slot_aad(
        version,
        flags,
        volume_uuid,
        slot_idx,
        slot_flags,
        kdf_params,
        &salt,
        pq_ciphertext.as_deref(),
    );
    let wrapped = wrap_master_secret(&effective_kek, &nonce, &aad, payload)?;

    Ok(KeySlot {
        active: true,
        requires_keyfile: auth.keyfile_hash.is_some(),
        pq_hybrid: pq_ciphertext.is_some(),
        kdf_params: *kdf_params,
        salt,
        nonce,
        wrapped_master_secret: wrapped,
        pq_ciphertext,
        label: label.to_string(),
    })
}

fn try_unlock_raw_header(
    raw: &[u8; HEADER_SIZE],
    auth: &AuthMaterial<'_>,
) -> Result<UnlockOutcome> {
    let header = VolumeHeader::deserialize(raw)?;

    for (idx, slot) in header.key_slots.iter().enumerate() {
        if !slot.active {
            continue;
        }
        if slot.requires_keyfile != auth.keyfile_hash.is_some() {
            continue;
        }
        if slot.pq_hybrid != auth.pq_keypair.is_some() {
            continue;
        }

        let classical_kek = derive_kek(
            auth.passphrase,
            auth.keyfile_hash,
            &slot.salt,
            &slot.kdf_params,
        )?;
        let effective_kek = if slot.pq_hybrid {
            let kp = auth.pq_keypair.ok_or(VolumeError::AuthenticationFailed)?;
            let ct = slot
                .pq_ciphertext
                .as_deref()
                .ok_or(VolumeError::InvalidHeader)?;
            let pq_ss = pq_decapsulate(&kp.dk, ct)?;
            combine_hybrid_kek(&classical_kek, &pq_ss, &slot.salt)?
        } else {
            classical_kek
        };

        let aad = VolumeHeader::build_slot_aad(
            header.version,
            header.flags,
            &header.volume_uuid,
            idx,
            slot.slot_flags_byte(),
            &slot.kdf_params,
            &slot.salt,
            slot.pq_ciphertext.as_deref(),
        );

        if let Ok(unwrapped) = unwrap_master_secret(
            &effective_kek,
            &slot.nonce,
            &aad,
            &slot.wrapped_master_secret,
        ) {
            if is_duress_payload(&unwrapped, &header.volume_uuid) {
                return Ok(UnlockOutcome::DuressTriggered);
            }
            let keys = VolumeKeys::derive_from_secret(unwrapped, &header.volume_uuid)?;
            VolumeHeader::verify_raw_mac(raw, keys.header_mac_key())?;
            return Ok(UnlockOutcome::Unlocked(Box::new(header), keys, idx));
        }
    }

    Err(VolumeError::AuthenticationFailed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::MemoryBlockDevice;
    use falcon_crypto::{analyze_entropy, hash_keyfile, KdfProfile};

    fn test_opts(
        bytes: u64,
        cascade: bool,
        detached: Option<PathBuf>,
        expires_at_unix: u64,
        max_failed_attempts: u32,
    ) -> CreateOptions {
        CreateOptions {
            data_bytes: bytes,
            kdf_params: KdfProfile::FastTest.params(),
            integrity_enabled: true,
            cipher_mode: if cascade {
                CipherMode::CascadeAesSerpentXts
            } else {
                CipherMode::Aes256Xts
            },
            detached_header_path: detached,
            expires_at_unix,
            max_failed_attempts,
            label: "primary".to_string(),
        }
    }

    #[test]
    fn hidden_volume_plausible_deniability_and_outer_verify_passes() {
        let dev = MemoryBlockDevice::new(0);
        let outer_auth = AuthMaterial::password_only(b"decoy-outer-pass");
        let hidden_auth = AuthMaterial::password_only(b"classified-inner-pass");

        // Create 2 MiB outer volume
        let mut outer = Volume::create(
            dev,
            &test_opts(2 * 1024 * 1024, false, None, 0, 0),
            &outer_auth,
            |_, _| {},
        )
        .unwrap();

        // Provision hidden volume in upper half
        let (_start, hidden_secs) = outer
            .create_hidden_in_outer(
                &hidden_auth,
                &KdfProfile::FastTest.params(),
                CipherMode::CascadeAesSerpentXts,
                "inner",
            )
            .unwrap();
        assert!(hidden_secs >= MIN_DATA_SECTORS);

        // Outer volume STILL passes 100% full integrity verification!
        assert!(outer.verify_all_sectors(|_, _| {}).unwrap().is_clean());

        // Zero `FLCNDSK1` magic anywhere inside the outer data area (excluding outer backup header)
        let data_slice = &outer.device.as_slice()
            [outer.header().data_offset as usize..outer.header().backup_header_offset as usize];
        assert!(
            !data_slice.windows(8).any(|w| w == b"FLCNDSK1"),
            "hidden header magic leaked!"
        );

        let backing = outer.device;
        // Open hidden volume cleanly with hidden passphrase
        let mut hidden = Volume::open_hidden(backing, &hidden_auth, None).unwrap();
        assert!(hidden.is_hidden());
        assert_eq!(
            hidden.header().cipher_mode(),
            CipherMode::CascadeAesSerpentXts
        );

        let pt = [0x99u8; SECTOR_SIZE];
        hidden.write_sector(1, &pt).unwrap();
        let mut out = [0u8; SECTOR_SIZE];
        hidden.read_sector(1, &mut out).unwrap();
        assert_eq!(out, pt);
        assert!(hidden.verify_all_sectors(|_, _| {}).unwrap().is_clean());
    }

    #[test]
    fn dead_mans_switch_auto_shred_after_max_strikes() {
        let tmp = std::env::temp_dir().join(format!("falcon_strikes_{}.flc", std::process::id()));
        let _ = std::fs::remove_file(&tmp);

        let dev = crate::FileBlockDevice::create(&tmp, 0, false).unwrap();
        let real = AuthMaterial::password_only(b"right-pass");
        let wrong = AuthMaterial::password_only(b"wrong-pass");

        let _vol = Volume::create(
            dev,
            &test_opts(512 * 1024, false, None, 0, 3),
            &real,
            |_, _| {},
        )
        .unwrap();

        // Strike 1 & 2 -> AuthenticationFailed
        for _ in 0..2 {
            let d = crate::FileBlockDevice::open_rw(&tmp, false).unwrap();
            assert!(matches!(
                Volume::open(d, &wrong, None),
                Err(VolumeError::AuthenticationFailed)
            ));
        }

        // Strike 3 -> AutoShredded!
        let d = crate::FileBlockDevice::open_rw(&tmp, false).unwrap();
        assert!(matches!(
            Volume::open(d, &wrong, None),
            Err(VolumeError::AutoShredded)
        ));

        // Even the real passphrase can never open it now
        let d = crate::FileBlockDevice::open_rw(&tmp, false).unwrap();
        assert!(Volume::open(d, &real, None).is_err());
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn mission_ttl_blocks_expired_volume() {
        let dev = MemoryBlockDevice::new(0);
        let auth = AuthMaterial::password_only(b"ttl-pass");
        // Expired in the past (UNIX 1000)
        let vol = Volume::create(
            dev,
            &test_opts(512 * 1024, false, None, 1000, 0),
            &auth,
            |_, _| {},
        )
        .unwrap();
        let backing = vol.device;
        assert!(matches!(
            Volume::open(backing, &auth, None),
            Err(VolumeError::VolumeExpired {
                expires_at_unix: 1000
            })
        ));
    }

    #[test]
    fn post_quantum_and_stealth_still_pass() {
        let kp = PqKeypair::generate();
        let kf = hash_keyfile(&b"keyfile"[..]).unwrap();
        let auth = AuthMaterial {
            passphrase: b"pq-pass",
            keyfile_hash: Some(kf.as_array()),
            pq_keypair: Some(&kp),
        };
        let hdr_path =
            std::env::temp_dir().join(format!("falcon_v3_stealth_{}.fhdr", std::process::id()));
        let dev = MemoryBlockDevice::new(0);
        let vol = Volume::create(
            dev,
            &test_opts(512 * 1024, true, Some(hdr_path.clone()), 0, 0),
            &auth,
            |_, _| {},
        )
        .unwrap();

        let ent = analyze_entropy(vol.device.as_slice());
        assert!(!ent.has_visible_magic && ent.shannon_bits_per_byte > 7.98);
        let reopened = Volume::open(vol.device, &auth, Some(&hdr_path)).unwrap();
        assert!(reopened.header().key_slots[0].pq_hybrid);
        let _ = std::fs::remove_file(&hdr_path);
    }
}
