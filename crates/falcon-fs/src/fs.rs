use crate::error::{FsError, Result};
use falcon_crypto::{
    create_signed_entry, encode_custody_jsonl, parse_custody_jsonl, verify_custody_chain,
    CustodyEntry, CustodyVerifyReport, SECTOR_SIZE,
};
use falcon_volume::{BlockDevice, Volume};
use sha2::{Digest, Sha256};
use std::io::{Cursor, Read, Write};
use std::time::{SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

pub const CUSTODY_LOG_PATH: &str = ".falcon/custody.log";

const FS_MAGIC: [u8; 8] = *b"FLCNFS01";
const FS_VERSION: u32 = 1;
const INODE_SIZE: usize = 256;
const INODES_PER_SECTOR: usize = SECTOR_SIZE / INODE_SIZE; // 16
const MAX_PATH_BYTES: usize = 160;
const INDEX_ENTRIES_PER_BLOCK: usize = (SECTOR_SIZE / 8) - 1; // 511

#[derive(Debug, Clone)]
struct Superblock {
    version: u32,
    total_sectors: u64,
    bitmap_start: u64,
    bitmap_sectors: u64,
    inode_start: u64,
    inode_sectors: u64,
    max_inodes: u64,
    data_start: u64,
}

impl Superblock {
    fn for_volume(total_sectors: u64) -> Result<Self> {
        let bitmap_start = 1u64;
        let bits_per_sector = (SECTOR_SIZE * 8) as u64;
        let bitmap_sectors = total_sectors.div_ceil(bits_per_sector);
        let inode_start = bitmap_start + bitmap_sectors;
        let inode_sectors = (total_sectors / 32).clamp(2, 512);
        let max_inodes = inode_sectors * (INODES_PER_SECTOR as u64);
        let data_start = inode_start + inode_sectors;

        if data_start + 8 > total_sectors {
            return Err(FsError::NoSpaceLeft);
        }

        Ok(Self {
            version: FS_VERSION,
            total_sectors,
            bitmap_start,
            bitmap_sectors,
            inode_start,
            inode_sectors,
            max_inodes,
            data_start,
        })
    }

    fn serialize(&self) -> [u8; SECTOR_SIZE] {
        let mut buf = [0u8; SECTOR_SIZE];
        buf[0..8].copy_from_slice(&FS_MAGIC);
        buf[8..12].copy_from_slice(&self.version.to_le_bytes());
        buf[12..20].copy_from_slice(&self.total_sectors.to_le_bytes());
        buf[20..28].copy_from_slice(&self.bitmap_start.to_le_bytes());
        buf[28..36].copy_from_slice(&self.bitmap_sectors.to_le_bytes());
        buf[36..44].copy_from_slice(&self.inode_start.to_le_bytes());
        buf[44..52].copy_from_slice(&self.inode_sectors.to_le_bytes());
        buf[52..60].copy_from_slice(&self.max_inodes.to_le_bytes());
        buf[60..68].copy_from_slice(&self.data_start.to_le_bytes());
        buf
    }

    fn deserialize(buf: &[u8; SECTOR_SIZE], volume_sectors: u64) -> Result<Self> {
        if buf[0..8] != FS_MAGIC {
            return Err(FsError::InvalidFilesystem);
        }
        let version = u32::from_le_bytes(buf[8..12].try_into().unwrap());
        if version != FS_VERSION {
            return Err(FsError::UnsupportedVersion(version));
        }
        let total_sectors = u64::from_le_bytes(buf[12..20].try_into().unwrap());
        let bitmap_start = u64::from_le_bytes(buf[20..28].try_into().unwrap());
        let bitmap_sectors = u64::from_le_bytes(buf[28..36].try_into().unwrap());
        let inode_start = u64::from_le_bytes(buf[36..44].try_into().unwrap());
        let inode_sectors = u64::from_le_bytes(buf[44..52].try_into().unwrap());
        let max_inodes = u64::from_le_bytes(buf[52..60].try_into().unwrap());
        let data_start = u64::from_le_bytes(buf[60..68].try_into().unwrap());

        let bits_per_sector = (SECTOR_SIZE * 8) as u64;
        let expected_bitmap_sectors = total_sectors.div_ceil(bits_per_sector);
        let expected_inode_start = bitmap_start.checked_add(bitmap_sectors);
        let expected_data_start = inode_start.checked_add(inode_sectors);
        let expected_max_inodes = inode_sectors.checked_mul(INODES_PER_SECTOR as u64);

        if total_sectors != volume_sectors
            || bitmap_start != 1
            || bitmap_sectors == 0
            || bitmap_sectors != expected_bitmap_sectors
            || expected_inode_start != Some(inode_start)
            || inode_sectors == 0
            || inode_sectors > 512
            || expected_max_inodes != Some(max_inodes)
            || expected_data_start != Some(data_start)
            || data_start >= total_sectors
        {
            return Err(FsError::CorruptedMetadata(
                "superblock geometry mismatch".to_string(),
            ));
        }

        Ok(Self {
            version,
            total_sectors,
            bitmap_start,
            bitmap_sectors,
            inode_start,
            inode_sectors,
            max_inodes,
            data_start,
        })
    }
}

#[derive(Debug, Clone)]
struct Inode {
    in_use: bool,
    file_size: u64,
    created_at: u64,
    modified_at: u64,
    extent_head_sector: u64,
    sha256: [u8; 32],
    path: String,
}

impl Inode {
    fn empty() -> Self {
        Self {
            in_use: false,
            file_size: 0,
            created_at: 0,
            modified_at: 0,
            extent_head_sector: 0,
            sha256: [0u8; 32],
            path: String::new(),
        }
    }

    fn serialize(&self, dst: &mut [u8; INODE_SIZE]) {
        dst.fill(0);
        if !self.in_use {
            return;
        }
        let path_bytes = self.path.as_bytes();
        let path_len = path_bytes.len().min(MAX_PATH_BYTES) as u16;

        dst[0] = 1;
        dst[2..4].copy_from_slice(&path_len.to_le_bytes());
        dst[4..12].copy_from_slice(&self.file_size.to_le_bytes());
        dst[12..20].copy_from_slice(&self.created_at.to_le_bytes());
        dst[20..28].copy_from_slice(&self.modified_at.to_le_bytes());
        dst[28..36].copy_from_slice(&self.extent_head_sector.to_le_bytes());
        dst[36..68].copy_from_slice(&self.sha256);
        dst[68..68 + path_len as usize].copy_from_slice(&path_bytes[..path_len as usize]);
    }

    fn deserialize(src: &[u8; INODE_SIZE]) -> Result<Self> {
        if src[0] == 0 {
            return Ok(Self::empty());
        }
        if src[0] != 1 {
            return Err(FsError::CorruptedMetadata(
                "bad inode state flag".to_string(),
            ));
        }
        let path_len = u16::from_le_bytes(src[2..4].try_into().unwrap()) as usize;
        if path_len == 0 || path_len > MAX_PATH_BYTES {
            return Err(FsError::CorruptedMetadata(
                "bad inode path length".to_string(),
            ));
        }
        let file_size = u64::from_le_bytes(src[4..12].try_into().unwrap());
        let created_at = u64::from_le_bytes(src[12..20].try_into().unwrap());
        let modified_at = u64::from_le_bytes(src[20..28].try_into().unwrap());
        let extent_head_sector = u64::from_le_bytes(src[28..36].try_into().unwrap());
        let mut sha256 = [0u8; 32];
        sha256.copy_from_slice(&src[36..68]);
        let path = String::from_utf8(src[68..68 + path_len].to_vec())
            .map_err(|_| FsError::CorruptedMetadata("non-UTF8 inode path".to_string()))?;

        Ok(Self {
            in_use: true,
            file_size,
            created_at,
            modified_at,
            extent_head_sector,
            sha256,
            path,
        })
    }
}

#[derive(Debug, Clone)]
pub struct FileEntry {
    pub path: String,
    pub size: u64,
    pub created_at: u64,
    pub modified_at: u64,
    pub sha256: [u8; 32],
}

#[derive(Debug, Clone)]
pub struct FsStats {
    pub total_sectors: u64,
    pub used_sectors: u64,
    pub free_sectors: u64,
    pub file_count: usize,
    pub max_files: u64,
}

pub struct FalconFs<D: BlockDevice> {
    volume: Volume<D>,
    sb: Superblock,
    bitmap: Vec<u8>,
}

impl<D: BlockDevice> FalconFs<D> {
    pub fn format(mut volume: Volume<D>) -> Result<Self> {
        let sb = Superblock::for_volume(volume.sector_count())?;
        volume.write_sector(0, &sb.serialize())?;

        let mut bitmap = vec![0u8; (sb.bitmap_sectors as usize) * SECTOR_SIZE];
        for s in 0..sb.data_start {
            set_bit(&mut bitmap, s, true);
        }

        for i in 0..sb.bitmap_sectors {
            let mut sec = [0u8; SECTOR_SIZE];
            let start = (i as usize) * SECTOR_SIZE;
            sec.copy_from_slice(&bitmap[start..start + SECTOR_SIZE]);
            volume.write_sector(sb.bitmap_start + i, &sec)?;
        }

        let empty = [0u8; SECTOR_SIZE];
        for i in 0..sb.inode_sectors {
            volume.write_sector(sb.inode_start + i, &empty)?;
        }

        volume.sync_all()?;
        Ok(Self { volume, sb, bitmap })
    }

    pub fn mount(mut volume: Volume<D>) -> Result<Self> {
        let mut sb_buf = [0u8; SECTOR_SIZE];
        volume.read_sector(0, &mut sb_buf)?;
        let sb = Superblock::deserialize(&sb_buf, volume.sector_count())?;

        let mut bitmap = vec![0u8; (sb.bitmap_sectors as usize) * SECTOR_SIZE];
        let mut sec = [0u8; SECTOR_SIZE];
        for i in 0..sb.bitmap_sectors {
            volume.read_sector(sb.bitmap_start + i, &mut sec)?;
            let start = (i as usize) * SECTOR_SIZE;
            bitmap[start..start + SECTOR_SIZE].copy_from_slice(&sec);
        }
        sec.zeroize();

        Ok(Self { volume, sb, bitmap })
    }

    pub fn volume(&self) -> &Volume<D> {
        &self.volume
    }

    pub fn volume_mut(&mut self) -> &mut Volume<D> {
        &mut self.volume
    }

    pub fn into_volume(self) -> Volume<D> {
        self.volume
    }

    pub fn list_files(&mut self) -> Result<Vec<FileEntry>> {
        let mut files = Vec::new();
        let mut sec = [0u8; SECTOR_SIZE];

        for i in 0..self.sb.inode_sectors {
            self.volume.read_sector(self.sb.inode_start + i, &mut sec)?;
            for j in 0..INODES_PER_SECTOR {
                let raw: &[u8; INODE_SIZE] = sec[j * INODE_SIZE..(j + 1) * INODE_SIZE]
                    .try_into()
                    .unwrap();
                let inode = Inode::deserialize(raw)?;
                if inode.in_use && inode.path != CUSTODY_LOG_PATH {
                    files.push(FileEntry {
                        path: inode.path,
                        size: inode.file_size,
                        created_at: inode.created_at,
                        modified_at: inode.modified_at,
                        sha256: inode.sha256,
                    });
                }
            }
        }
        sec.zeroize();
        files.sort_by(|a, b| a.path.cmp(&b.path));
        Ok(files)
    }

    pub fn stats(&mut self) -> Result<FsStats> {
        let files = self.list_files()?;
        let used = (0..self.sb.total_sectors)
            .filter(|&s| get_bit(&self.bitmap, s))
            .count() as u64;
        Ok(FsStats {
            total_sectors: self.sb.total_sectors,
            used_sectors: used,
            free_sectors: self.sb.total_sectors.saturating_sub(used),
            file_count: files.len(),
            max_files: self.sb.max_inodes,
        })
    }

    pub fn put_file<R: Read>(&mut self, vault_path: &str, reader: R) -> Result<FileEntry> {
        self.put_file_opts(vault_path, reader, false)
    }

    pub fn put_file_opts<R: Read>(
        &mut self,
        vault_path: &str,
        mut reader: R,
        zero_timestamps: bool,
    ) -> Result<FileEntry> {
        let norm_path = normalize_path(vault_path)?;
        if norm_path == CUSTODY_LOG_PATH {
            return Err(FsError::InvalidPath(vault_path.to_string()));
        }
        self.put_file_internal(&norm_path, &mut reader, zero_timestamps)
    }

    fn put_file_internal<R: Read>(
        &mut self,
        norm_path: &str,
        reader: &mut R,
        zero_timestamps: bool,
    ) -> Result<FileEntry> {
        if self.find_inode(norm_path)?.is_some() {
            self.remove_file_internal(norm_path)?;
        }

        let inode_idx = self.find_free_inode()?.ok_or(FsError::NoInodesLeft)?;
        let mut allocated: Vec<u64> = Vec::new();
        let mut data_sectors: Vec<u64> = Vec::new();
        let mut hasher = Sha256::new();
        let mut total_bytes: u64 = 0;
        let mut buf = [0u8; SECTOR_SIZE];

        loop {
            let n = read_full_or_eof(reader, &mut buf)?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
            total_bytes += n as u64;
            if n < SECTOR_SIZE {
                buf[n..].fill(0);
            }

            let sector = match self.alloc_sector() {
                Ok(s) => s,
                Err(e) => {
                    buf.zeroize();
                    self.rollback(&allocated);
                    return Err(e);
                }
            };
            allocated.push(sector);
            data_sectors.push(sector);

            if let Err(e) = self.volume.write_sector(sector, &buf) {
                buf.zeroize();
                self.rollback(&allocated);
                return Err(e.into());
            }

            if n < SECTOR_SIZE {
                break;
            }
        }
        buf.zeroize();

        let extent_head_sector = if data_sectors.is_empty() {
            0
        } else {
            let num_blocks = data_sectors.len().div_ceil(INDEX_ENTRIES_PER_BLOCK);
            let mut idx_sectors = Vec::with_capacity(num_blocks);
            for _ in 0..num_blocks {
                match self.alloc_sector() {
                    Ok(s) => {
                        allocated.push(s);
                        idx_sectors.push(s);
                    }
                    Err(e) => {
                        self.rollback(&allocated);
                        return Err(e);
                    }
                }
            }

            for (blk_i, &idx_sec) in idx_sectors.iter().enumerate() {
                let mut idx_buf = [0u8; SECTOR_SIZE];
                let next_sec = idx_sectors.get(blk_i + 1).copied().unwrap_or(0);
                idx_buf[0..8].copy_from_slice(&next_sec.to_le_bytes());

                let start = blk_i * INDEX_ENTRIES_PER_BLOCK;
                let end = (start + INDEX_ENTRIES_PER_BLOCK).min(data_sectors.len());
                for (entry_i, &d_sec) in data_sectors[start..end].iter().enumerate() {
                    let off = 8 + entry_i * 8;
                    idx_buf[off..off + 8].copy_from_slice(&d_sec.to_le_bytes());
                }

                if let Err(e) = self.volume.write_sector(idx_sec, &idx_buf) {
                    self.rollback(&allocated);
                    return Err(e.into());
                }
            }

            idx_sectors[0]
        };

        let now = if zero_timestamps { 0 } else { unix_now() };
        let sha256: [u8; 32] = hasher.finalize().into();

        let inode = Inode {
            in_use: true,
            file_size: total_bytes,
            created_at: now,
            modified_at: now,
            extent_head_sector,
            sha256,
            path: norm_path.to_string(),
        };

        self.write_inode(inode_idx, &inode)?;
        self.flush_bitmap()?;
        self.volume.sync_all()?;

        Ok(FileEntry {
            path: norm_path.to_string(),
            size: total_bytes,
            created_at: now,
            modified_at: now,
            sha256,
        })
    }

    pub fn is_upper_half_free(&self) -> bool {
        let start = self.sb.total_sectors / 2;
        (start..self.sb.total_sectors).all(|s| !get_bit(&self.bitmap, s))
    }

    pub fn read_custody_log(&mut self) -> Result<Vec<CustodyEntry>> {
        if self.find_inode(CUSTODY_LOG_PATH)?.is_none() {
            return Ok(Vec::new());
        }
        let mut buf = Vec::new();
        self.get_file(CUSTODY_LOG_PATH, &mut buf)?;
        let text = String::from_utf8(buf)
            .map_err(|_| FsError::CorruptedMetadata("custody log is not UTF-8".into()))?;
        parse_custody_jsonl(&text)
            .map_err(|_| FsError::CorruptedMetadata("malformed custody log".into()))
    }

    pub fn append_custody_event(&mut self, event: &str, detail: &str) -> Result<CustodyEntry> {
        let mut entries = self.read_custody_log()?;
        let sk = self.volume.custody_signing_key();
        let slot = self.volume.unlocked_slot();
        let entry = create_signed_entry(&sk, entries.last(), event, slot, detail);
        entries.push(entry.clone());
        let encoded = encode_custody_jsonl(&entries);
        let mut cursor = Cursor::new(encoded.as_bytes());
        self.put_file_internal(CUSTODY_LOG_PATH, &mut cursor, false)?;
        Ok(entry)
    }

    pub fn verify_custody_log(&mut self) -> Result<CustodyVerifyReport> {
        let entries = self.read_custody_log()?;
        let vk = self.volume.custody_verifying_key();
        Ok(verify_custody_chain(&entries, &vk))
    }

    pub fn get_file<W: Write>(&mut self, vault_path: &str, mut writer: W) -> Result<FileEntry> {
        let norm_path = normalize_path(vault_path)?;
        let (_, inode) = self
            .find_inode(&norm_path)?
            .ok_or_else(|| FsError::NotFound(norm_path.clone()))?;

        let mut remaining = inode.file_size;
        let mut hasher = Sha256::new();
        let mut data_buf = [0u8; SECTOR_SIZE];
        let mut idx_buf = [0u8; SECTOR_SIZE];

        let mut cur = inode.extent_head_sector;
        let mut hops = 0u64;

        while cur != 0 && remaining > 0 {
            hops += 1;
            if hops > self.sb.total_sectors {
                return Err(FsError::CorruptedMetadata(
                    "cyclic extent chain".to_string(),
                ));
            }
            if cur < self.sb.data_start || cur >= self.sb.total_sectors {
                return Err(FsError::CorruptedMetadata(
                    "extent index sector out of data bounds".to_string(),
                ));
            }

            self.volume.read_sector(cur, &mut idx_buf)?;
            let next_idx = u64::from_le_bytes(idx_buf[0..8].try_into().unwrap());

            for entry_i in 0..INDEX_ENTRIES_PER_BLOCK {
                if remaining == 0 {
                    break;
                }
                let off = 8 + entry_i * 8;
                let data_sec = u64::from_le_bytes(idx_buf[off..off + 8].try_into().unwrap());
                if data_sec == 0 {
                    break;
                }
                if data_sec < self.sb.data_start || data_sec >= self.sb.total_sectors {
                    return Err(FsError::CorruptedMetadata(
                        "extent data sector out of data bounds".to_string(),
                    ));
                }

                self.volume.read_sector(data_sec, &mut data_buf)?;
                let n = remaining.min(SECTOR_SIZE as u64) as usize;
                hasher.update(&data_buf[..n]);
                writer.write_all(&data_buf[..n])?;
                remaining -= n as u64;
            }

            cur = next_idx;
        }

        data_buf.zeroize();
        idx_buf.zeroize();

        if remaining != 0 {
            return Err(FsError::CorruptedMetadata(format!(
                "truncated extent chain ({remaining} bytes short)"
            )));
        }

        let actual: [u8; 32] = hasher.finalize().into();
        if !bool::from(actual.ct_eq(&inode.sha256)) {
            return Err(FsError::FileChecksumMismatch(norm_path));
        }

        writer.flush()?;

        Ok(FileEntry {
            path: inode.path,
            size: inode.file_size,
            created_at: inode.created_at,
            modified_at: inode.modified_at,
            sha256: inode.sha256,
        })
    }

    pub fn remove_file(&mut self, vault_path: &str) -> Result<()> {
        let norm_path = normalize_path(vault_path)?;
        if norm_path == CUSTODY_LOG_PATH {
            return Err(FsError::InvalidPath(vault_path.to_string()));
        }
        self.remove_file_internal(&norm_path)
    }

    fn remove_file_internal(&mut self, norm_path: &str) -> Result<()> {
        let (inode_idx, inode) = self
            .find_inode(norm_path)?
            .ok_or_else(|| FsError::NotFound(norm_path.to_string()))?;

        let mut to_erase: Vec<u64> = Vec::new();
        let mut idx_buf = [0u8; SECTOR_SIZE];
        let mut cur = inode.extent_head_sector;
        let mut hops = 0u64;

        while cur != 0 {
            hops += 1;
            if hops > self.sb.total_sectors {
                return Err(FsError::CorruptedMetadata(
                    "cyclic extent chain during delete".to_string(),
                ));
            }
            if cur < self.sb.data_start || cur >= self.sb.total_sectors {
                return Err(FsError::CorruptedMetadata(
                    "extent index sector out of bounds during delete".to_string(),
                ));
            }
            self.volume.read_sector(cur, &mut idx_buf)?;
            let next_idx = u64::from_le_bytes(idx_buf[0..8].try_into().unwrap());

            for entry_i in 0..INDEX_ENTRIES_PER_BLOCK {
                let off = 8 + entry_i * 8;
                let data_sec = u64::from_le_bytes(idx_buf[off..off + 8].try_into().unwrap());
                if data_sec != 0 {
                    to_erase.push(data_sec);
                }
            }
            to_erase.push(cur);
            cur = next_idx;
        }
        idx_buf.zeroize();

        // Overwrite freed data and index sectors with encrypted noise so deleted
        // contents don't linger in unallocated space.
        for &sec in &to_erase {
            if sec >= self.sb.data_start && sec < self.sb.total_sectors {
                self.volume.erase_sector(sec)?;
                set_bit(&mut self.bitmap, sec, false);
            }
        }

        self.write_inode(inode_idx, &Inode::empty())?;
        self.flush_bitmap()?;
        self.volume.sync_all()?;
        Ok(())
    }

    fn alloc_sector(&mut self) -> Result<u64> {
        for s in self.sb.data_start..self.sb.total_sectors {
            if !get_bit(&self.bitmap, s) {
                set_bit(&mut self.bitmap, s, true);
                return Ok(s);
            }
        }
        Err(FsError::NoSpaceLeft)
    }

    fn rollback(&mut self, sectors: &[u64]) {
        for &s in sectors {
            set_bit(&mut self.bitmap, s, false);
        }
    }

    fn flush_bitmap(&mut self) -> Result<()> {
        for i in 0..self.sb.bitmap_sectors {
            let mut sec = [0u8; SECTOR_SIZE];
            let start = (i as usize) * SECTOR_SIZE;
            sec.copy_from_slice(&self.bitmap[start..start + SECTOR_SIZE]);
            self.volume.write_sector(self.sb.bitmap_start + i, &sec)?;
        }
        Ok(())
    }

    fn find_inode(&mut self, norm_path: &str) -> Result<Option<(usize, Inode)>> {
        let mut sec = [0u8; SECTOR_SIZE];
        for i in 0..self.sb.inode_sectors {
            self.volume.read_sector(self.sb.inode_start + i, &mut sec)?;
            for j in 0..INODES_PER_SECTOR {
                let raw: &[u8; INODE_SIZE] = sec[j * INODE_SIZE..(j + 1) * INODE_SIZE]
                    .try_into()
                    .unwrap();
                let inode = Inode::deserialize(raw)?;
                if inode.in_use && inode.path == norm_path {
                    sec.zeroize();
                    return Ok(Some(((i as usize) * INODES_PER_SECTOR + j, inode)));
                }
            }
        }
        sec.zeroize();
        Ok(None)
    }

    fn find_free_inode(&mut self) -> Result<Option<usize>> {
        let mut sec = [0u8; SECTOR_SIZE];
        for i in 0..self.sb.inode_sectors {
            self.volume.read_sector(self.sb.inode_start + i, &mut sec)?;
            for j in 0..INODES_PER_SECTOR {
                if sec[j * INODE_SIZE] == 0 {
                    sec.zeroize();
                    return Ok(Some((i as usize) * INODES_PER_SECTOR + j));
                }
            }
        }
        sec.zeroize();
        Ok(None)
    }

    fn write_inode(&mut self, inode_idx: usize, inode: &Inode) -> Result<()> {
        let sec_offset = (inode_idx / INODES_PER_SECTOR) as u64;
        let slot_in_sec = inode_idx % INODES_PER_SECTOR;
        let target = self.sb.inode_start + sec_offset;

        let mut sec = [0u8; SECTOR_SIZE];
        self.volume.read_sector(target, &mut sec)?;

        let mut encoded = [0u8; INODE_SIZE];
        inode.serialize(&mut encoded);
        sec[slot_in_sec * INODE_SIZE..(slot_in_sec + 1) * INODE_SIZE].copy_from_slice(&encoded);

        self.volume.write_sector(target, &sec)?;
        sec.zeroize();
        Ok(())
    }
}

pub fn normalize_path(input: &str) -> Result<String> {
    let cleaned = input.replace('\\', "/");
    let trimmed = cleaned.trim_matches('/');
    if trimmed.is_empty() || trimmed.len() > MAX_PATH_BYTES {
        return Err(FsError::InvalidPath(input.to_string()));
    }
    let mut parts = Vec::new();
    for seg in trimmed.split('/') {
        if seg.is_empty() || seg == "." || seg == ".." || seg.contains('\0') {
            return Err(FsError::InvalidPath(input.to_string()));
        }
        parts.push(seg);
    }
    let normalized = parts.join("/");
    if normalized.len() > MAX_PATH_BYTES {
        return Err(FsError::InvalidPath(input.to_string()));
    }
    Ok(normalized)
}

fn read_full_or_eof<R: Read>(reader: &mut R, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        match reader.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(filled)
}

fn get_bit(bitmap: &[u8], idx: u64) -> bool {
    let Ok(byte_idx) = usize::try_from(idx / 8) else {
        return true;
    };
    bitmap
        .get(byte_idx)
        .map(|&b| (b & (1u8 << (idx % 8))) != 0)
        .unwrap_or(true)
}

fn set_bit(bitmap: &mut [u8], idx: u64, val: bool) {
    let Ok(byte_idx) = usize::try_from(idx / 8) else {
        return;
    };
    if let Some(byte) = bitmap.get_mut(byte_idx) {
        let mask = 1u8 << (idx % 8);
        if val {
            *byte |= mask;
        } else {
            *byte &= !mask;
        }
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use falcon_crypto::{CipherMode, KdfProfile};
    use falcon_volume::{AuthMaterial, CreateOptions, MemoryBlockDevice};

    fn make_fs(bytes: u64) -> FalconFs<MemoryBlockDevice> {
        let dev = MemoryBlockDevice::new(0);
        let opts = CreateOptions {
            data_bytes: bytes,
            kdf_params: KdfProfile::FastTest.params(),
            integrity_enabled: true,
            cipher_mode: CipherMode::Aes256Xts,
            detached_header_path: None,
            expires_at_unix: 0,
            max_failed_attempts: 0,
            label: "fs-test".to_string(),
        };
        let vol = Volume::create(
            dev,
            &opts,
            &AuthMaterial::password_only(b"fs-pass"),
            |_, _| {},
        )
        .unwrap();
        FalconFs::format(vol).unwrap()
    }

    #[test]
    fn put_get_overwrite_and_remove() {
        let mut fs = make_fs(1024 * 1024);

        let payload: Vec<u8> = (0..50_000).map(|i| ((i * 31) & 0xFF) as u8).collect();
        let entry = fs.put_file("docs/archive.bin", &payload[..]).unwrap();
        assert_eq!(entry.size, payload.len() as u64);

        fs.put_file("empty.txt", &b""[..]).unwrap();

        let list = fs.list_files().unwrap();
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].path, "docs/archive.bin");
        assert_eq!(list[1].path, "empty.txt");

        let mut out = Vec::new();
        fs.get_file("docs/archive.bin", &mut out).unwrap();
        assert_eq!(out, payload);

        let mut empty_out = Vec::new();
        fs.get_file("empty.txt", &mut empty_out).unwrap();
        assert!(empty_out.is_empty());

        fs.put_file("docs/archive.bin", &b"v2-content"[..]).unwrap();
        let mut v2 = Vec::new();
        fs.get_file("docs/archive.bin", &mut v2).unwrap();
        assert_eq!(v2, b"v2-content");

        fs.remove_file("docs/archive.bin").unwrap();
        assert!(matches!(
            fs.get_file("docs/archive.bin", &mut Vec::new()),
            Err(FsError::NotFound(_))
        ));

        assert!(fs
            .volume_mut()
            .verify_all_sectors(|_, _| {})
            .unwrap()
            .is_clean());
    }

    #[test]
    fn rejects_bad_paths() {
        assert!(normalize_path("../etc/passwd").is_err());
        assert!(normalize_path("a/../../b").is_err());
        assert!(normalize_path("").is_err());
        assert_eq!(normalize_path("/docs/notes.txt").unwrap(), "docs/notes.txt");
    }

    #[test]
    fn custody_log_and_opsec_zero_timestamps() {
        let mut fs = make_fs(1024 * 1024);
        let entry = fs.put_file_opts("clean.bin", &b"secret"[..], true).unwrap();
        assert_eq!(entry.created_at, 0);
        assert_eq!(entry.modified_at, 0);

        fs.append_custody_event("CREATE", "initialized").unwrap();
        fs.append_custody_event("PUT", "clean.bin").unwrap();

        // Custody log is internal and hidden from normal user file listing
        assert_eq!(fs.list_files().unwrap().len(), 1);
        let rep = fs.verify_custody_log().unwrap();
        assert!(rep.valid);
        assert_eq!(rep.entry_count, 2);
    }
}
