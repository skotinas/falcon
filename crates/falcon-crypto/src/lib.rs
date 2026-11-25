pub mod custody;
pub mod diagnostics;
pub mod error;
pub mod integrity;
pub mod kdf;
pub mod memory;
pub mod post;
pub mod pq;
pub mod qr;
pub mod sanitize;
pub mod seal;
pub mod shamir;
pub mod wrap;
pub mod xts;

pub use custody::{
    create_signed_entry, encode_custody_jsonl, parse_custody_jsonl, verify_custody_chain,
    CustodyEntry, CustodyVerifyReport,
};
pub use diagnostics::{analyze_entropy, run_crypto_benchmark, BenchmarkReport, EntropyReport};
pub use error::{CryptoError, Result};
pub use integrity::{
    compute_header_mac, compute_sector_tag, verify_header_mac, verify_sector_tag, TAG_SIZE,
};
pub use kdf::{derive_kek, hash_keyfile, KdfParams, KdfProfile};
pub use memory::{harden_process, SecureArray, SecureBytes};
pub use post::{run_power_on_self_test, PostCheck, PostReport};
pub use pq::{
    combine_hybrid_kek, pq_decapsulate, pq_encapsulate, PqKeypair, PQ_CT_SIZE, PQ_DK_SIZE,
    PQ_EK_SIZE, PQ_KEYFILE_SIZE,
};
pub use qr::{render_keycard_svg, render_qr_svg, render_terminal_qr};
pub use sanitize::{sanitize_file_bytes, SanitizeReport};
pub use seal::{
    seal_package, unseal_package, OperatorIdentity, OperatorPublicBundle, SealedDropMeta,
    UnsealedDrop, IDENTITY_SIZE, PUB_BUNDLE_SIZE,
};
pub use shamir::{combine_shares, split_secret, Share};
pub use wrap::{
    apply_hidden_header_mask, build_duress_payload, duress_sentinel, is_duress_payload,
    random_bytes, unwrap_master_secret, wrap_master_secret, VolumeKeys, MASTER_SECRET_SIZE,
    WRAPPED_SECRET_SIZE, WRAP_NONCE_SIZE,
};
pub use xts::{CipherMode, XtsCipher, SECTOR_SIZE};
