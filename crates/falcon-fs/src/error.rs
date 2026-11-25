use falcon_volume::VolumeError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum FsError {
    #[error("volume error: {0}")]
    Volume(#[from] VolumeError),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("volume does not contain a valid FalconFS filesystem")]
    InvalidFilesystem,

    #[error("unsupported FalconFS version: {0}")]
    UnsupportedVersion(u32),

    #[error("invalid vault path '{0}'")]
    InvalidPath(String),

    #[error("file not found: '{0}'")]
    NotFound(String),

    #[error("no free space left in volume")]
    NoSpaceLeft,

    #[error("no free inode slots left")]
    NoInodesLeft,

    #[error("SHA-256 mismatch for '{0}'")]
    FileChecksumMismatch(String),

    #[error("corrupted filesystem metadata: {0}")]
    CorruptedMetadata(String),
}

pub type Result<T> = std::result::Result<T, FsError>;
