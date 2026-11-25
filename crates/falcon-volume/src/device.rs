use crate::error::{Result, VolumeError};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

pub trait BlockDevice {
    fn read_exact_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<()>;
    fn write_all_at(&mut self, offset: u64, buf: &[u8]) -> Result<()>;
    fn sync_all(&mut self) -> Result<()>;
    fn total_size(&mut self) -> Result<u64>;
    fn set_len(&mut self, size: u64) -> Result<()>;
}

pub fn is_raw_device_path(path: &Path) -> bool {
    let s = path.to_string_lossy();
    s.starts_with("/dev/") || s.starts_with(r"\\.\") || s.starts_with(r"\\?\")
}

// Block obvious boot/root disks so a typo can't wipe the host OS.
pub fn is_protected_system_disk(path: &Path) -> bool {
    let s = path.to_string_lossy().to_lowercase();
    matches!(
        s.as_str(),
        "/dev/disk0"
            | "/dev/rdisk0"
            | "/dev/disk1"
            | "/dev/rdisk1"
            | "/dev/sda"
            | "/dev/vda"
            | "/dev/nvme0n1"
            | r"\\.\physicaldrive0"
    ) || s.starts_with("/dev/disk0s")
        || s.starts_with("/dev/rdisk0s")
        || s.starts_with("/dev/sda1")
        || s.starts_with("/dev/nvme0n1p1")
}

pub struct FileBlockDevice {
    file: File,
    is_raw: bool,
}

impl FileBlockDevice {
    pub fn create(path: &Path, total_bytes: u64, allow_raw: bool) -> Result<Self> {
        let raw = is_raw_device_path(path);
        if raw {
            if is_protected_system_disk(path) {
                return Err(VolumeError::ProtectedSystemDisk {
                    path: path.display().to_string(),
                });
            }
            if !allow_raw {
                return Err(VolumeError::RawDeviceGuard {
                    path: path.display().to_string(),
                });
            }
            let file = OpenOptions::new().read(true).write(true).open(path)?;
            return Ok(Self { file, is_raw: true });
        }

        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(path)?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = file.set_permissions(std::fs::Permissions::from_mode(0o600));
        }

        file.set_len(total_bytes)?;
        Ok(Self {
            file,
            is_raw: false,
        })
    }

    pub fn open_rw(path: &Path, allow_raw: bool) -> Result<Self> {
        let raw = is_raw_device_path(path);
        if raw && !allow_raw {
            return Err(VolumeError::RawDeviceGuard {
                path: path.display().to_string(),
            });
        }
        let file = OpenOptions::new().read(true).write(true).open(path)?;
        Ok(Self { file, is_raw: raw })
    }

    pub fn open_ro(path: &Path) -> Result<Self> {
        let raw = is_raw_device_path(path);
        let file = OpenOptions::new().read(true).open(path)?;
        Ok(Self { file, is_raw: raw })
    }
}

impl BlockDevice for FileBlockDevice {
    fn read_exact_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<()> {
        self.file.seek(SeekFrom::Start(offset))?;
        self.file.read_exact(buf)?;
        Ok(())
    }

    fn write_all_at(&mut self, offset: u64, buf: &[u8]) -> Result<()> {
        self.file.seek(SeekFrom::Start(offset))?;
        self.file.write_all(buf)?;
        Ok(())
    }

    fn sync_all(&mut self) -> Result<()> {
        self.file.sync_all()?;
        Ok(())
    }

    fn total_size(&mut self) -> Result<u64> {
        Ok(self.file.seek(SeekFrom::End(0))?)
    }

    fn set_len(&mut self, size: u64) -> Result<()> {
        if !self.is_raw {
            self.file.set_len(size)?;
        }
        Ok(())
    }
}

#[derive(Clone)]
pub struct MemoryBlockDevice {
    data: Vec<u8>,
}

impl MemoryBlockDevice {
    pub fn new(size: usize) -> Self {
        Self {
            data: vec![0u8; size],
        }
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data
    }
}

impl BlockDevice for MemoryBlockDevice {
    fn read_exact_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<()> {
        let start = offset as usize;
        let end = start.checked_add(buf.len()).ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "offset overflow")
        })?;
        if end > self.data.len() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "read past end of memory device",
            )
            .into());
        }
        buf.copy_from_slice(&self.data[start..end]);
        Ok(())
    }

    fn write_all_at(&mut self, offset: u64, buf: &[u8]) -> Result<()> {
        let start = offset as usize;
        let end = start.checked_add(buf.len()).ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "offset overflow")
        })?;
        if end > self.data.len() {
            self.data.resize(end, 0);
        }
        self.data[start..end].copy_from_slice(buf);
        Ok(())
    }

    fn sync_all(&mut self) -> Result<()> {
        Ok(())
    }

    fn total_size(&mut self) -> Result<u64> {
        Ok(self.data.len() as u64)
    }

    fn set_len(&mut self, size: u64) -> Result<()> {
        self.data.resize(size as usize, 0);
        Ok(())
    }
}
