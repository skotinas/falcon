use thiserror::Error;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("bad key length: expected {expected}, got {actual}")]
    InvalidKeyLength { expected: usize, actual: usize },

    #[error("XTS keys K1 and K2 cannot be identical")]
    IdenticalXtsKeys,

    #[error("bad sector length: expected {expected}, got {actual}")]
    InvalidSectorLength { expected: usize, actual: usize },

    #[error("invalid KDF parameters: {0}")]
    InvalidKdfParams(String),

    #[error("key derivation failed: {0}")]
    KdfFailed(String),

    #[error("HKDF expand failed")]
    HkdfFailed,

    #[error("failed to unwrap key (wrong passphrase/keyfile or corrupted slot)")]
    UnwrapFailed,

    #[error("failed to wrap key")]
    WrapFailed,

    #[error("MAC verification failed")]
    IntegrityCheckFailed,

    #[error("post-quantum ML-KEM error: {0}")]
    PostQuantumError(String),

    #[error("Shamir secret sharing error: {0}")]
    ShamirError(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, CryptoError>;
