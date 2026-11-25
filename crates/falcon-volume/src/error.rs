use falcon_crypto::CryptoError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum VolumeError {
    #[error("crypto error: {0}")]
    Crypto(#[from] CryptoError),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("invalid or missing Falcon volume header")]
    InvalidHeader,

    #[error("unsupported volume format version: {0}")]
    UnsupportedVersion(u32),

    #[error("header MAC mismatch (possible tampering)")]
    HeaderTampered,

    #[error("authentication failed: check passphrase, keyfile, or key slot")]
    AuthenticationFailed,

    #[error("volume expired (Mission TTL elapsed at UNIX {expires_at_unix})")]
    VolumeExpired { expires_at_unix: u64 },

    #[error("dead-man's switch triggered: max failed attempts reached — volume auto-shredded")]
    AutoShredded,

    #[error("integrity check failed at data sector {sector}")]
    TamperDetected { sector: u64 },

    #[error("sector {sector} out of bounds (total: {total})")]
    SectorOutOfBounds { sector: u64, total: u64 },

    #[error("invalid key slot {0} (expected 0..4)")]
    InvalidKeySlot(usize),

    #[error("key slot {0} is already in use")]
    KeySlotOccupied(usize),

    #[error("key slot {0} is empty")]
    KeySlotEmpty(usize),

    #[error("cannot remove the last active key slot")]
    LastKeySlot,

    #[error("all 4 key slots are full")]
    NoFreeKeySlot,

    #[error("volume too small: need at least {min_bytes} bytes, got {requested_bytes}")]
    VolumeTooSmall {
        min_bytes: u64,
        requested_bytes: u64,
    },

    #[error("hidden volume error: {0}")]
    HiddenVolume(String),

    #[error("refusing to open raw device '{path}' without --raw-device")]
    RawDeviceGuard { path: String },

    #[error("refusing to touch system disk '{path}'")]
    ProtectedSystemDisk { path: String },

    #[error("bad backup header size: expected {expected} bytes, got {actual}")]
    InvalidBackupHeaderSize { expected: usize, actual: usize },
}

pub type Result<T> = std::result::Result<T, VolumeError>;
