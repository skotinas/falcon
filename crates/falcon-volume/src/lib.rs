pub mod device;
pub mod error;
pub mod header;
pub mod volume;

pub use device::{
    is_protected_system_disk, is_raw_device_path, BlockDevice, FileBlockDevice, MemoryBlockDevice,
};
pub use error::{Result, VolumeError};
pub use header::{
    KeySlot, VolumeHeader, VolumeLayout, FLAG_CASCADE_CIPHER, FLAG_DETACHED_HEADER,
    FLAG_HAS_BACKUP_HEADER, FLAG_HIDDEN_VOLUME, FLAG_INTEGRITY_ENABLED, FORMAT_VERSION,
    HEADER_MAGIC, HEADER_SIZE, MAX_KEY_SLOTS, MIN_DATA_SECTORS,
};
pub use volume::{AuthMaterial, CreateOptions, VerifyReport, Volume};
