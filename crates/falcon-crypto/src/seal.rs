use crate::error::{CryptoError, Result};
use crate::memory::SecureArray;
use crate::pq::{pq_decapsulate, pq_encapsulate, PqKeypair, PQ_CT_SIZE, PQ_DK_SIZE, PQ_EK_SIZE};
use crate::sanitize::{sanitize_file_bytes, SanitizeReport};
use crate::wrap::random_bytes;
use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use serde::Serialize;
use sha2::Sha512;
use std::time::{SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

pub const IDENTITY_MAGIC: [u8; 8] = *b"FLCNID01";
pub const PUB_BUNDLE_MAGIC: [u8; 8] = *b"FLCNPB01";
pub const SEAL_MAGIC: [u8; 8] = *b"FLCNPK01";
pub const SEAL_VERSION: u32 = 1;

pub const CALLSIGN_MAX_BYTES: usize = 32;
pub const PUB_BUNDLE_SIZE: usize = 8 + CALLSIGN_MAX_BYTES + PQ_EK_SIZE + 32; // 1640 bytes
pub const IDENTITY_SIZE: usize = 8 + CALLSIGN_MAX_BYTES + PQ_EK_SIZE + PQ_DK_SIZE + 32; // 4808 bytes

const SEAL_HEADER_SIZE: usize = 8 + 4 + 4 + 8 + 32 + 32 + 32 + 12 + PQ_CT_SIZE + 8; // 1708 bytes
const SEAL_SIG_SIZE: usize = 64;
const SEAL_FLAG_SANITIZED: u32 = 1 << 0;
const SEAL_CEK_INFO: &[u8] = b"falcon-v4-sealed-drop-cek";
const SEAL_SIG_DOMAIN: &[u8] = b"falcon-v4-sealed-drop-sig";
const MAX_FILENAME_BYTES: usize = 255;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OperatorPublicBundle {
    pub callsign: String,
    pub pq_ek: [u8; PQ_EK_SIZE],
    pub ed25519_vk: [u8; 32],
}

impl OperatorPublicBundle {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(PUB_BUNDLE_SIZE);
        out.extend_from_slice(&PUB_BUNDLE_MAGIC);
        out.extend_from_slice(&encode_callsign(&self.callsign));
        out.extend_from_slice(&self.pq_ek);
        out.extend_from_slice(&self.ed25519_vk);
        out
    }

    pub fn from_bytes(raw: &[u8]) -> Result<Self> {
        if raw.len() != PUB_BUNDLE_SIZE || raw[0..8] != PUB_BUNDLE_MAGIC {
            return Err(CryptoError::PostQuantumError(
                "invalid operator public bundle format".into(),
            ));
        }
        let callsign = decode_callsign(&raw[8..8 + CALLSIGN_MAX_BYTES])?;

        let ek_off = 8 + CALLSIGN_MAX_BYTES;
        let mut pq_ek = [0u8; PQ_EK_SIZE];
        pq_ek.copy_from_slice(&raw[ek_off..ek_off + PQ_EK_SIZE]);

        let vk_off = ek_off + PQ_EK_SIZE;
        let mut ed25519_vk = [0u8; 32];
        ed25519_vk.copy_from_slice(&raw[vk_off..vk_off + 32]);

        // Validate Ed25519 verifying key point encoding upfront.
        VerifyingKey::from_bytes(&ed25519_vk)
            .map_err(|_| CryptoError::PostQuantumError("invalid Ed25519 public key".into()))?;

        Ok(Self {
            callsign,
            pq_ek,
            ed25519_vk,
        })
    }

    pub fn key_hash(&self) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        h.update(b"falcon-v4-operator-id-hash");
        h.update(&self.pq_ek);
        h.update(&self.ed25519_vk);
        *h.finalize().as_bytes()
    }

    pub fn fingerprint_hex(&self) -> String {
        hex::encode(&self.key_hash()[..12])
    }

    pub fn ed25519_hex(&self) -> String {
        hex::encode(self.ed25519_vk)
    }
}

pub struct OperatorIdentity {
    pub callsign: String,
    pub pq_keypair: PqKeypair,
    pub signing_seed: SecureArray<32>,
}

impl OperatorIdentity {
    pub fn generate(callsign: &str) -> Self {
        let pq_keypair = PqKeypair::generate();
        let mut seed_raw = random_bytes::<32>();
        let signing_seed = SecureArray::from_mut_array(&mut seed_raw);
        Self {
            callsign: sanitize_callsign(callsign),
            pq_keypair,
            signing_seed,
        }
    }

    pub fn signing_key(&self) -> SigningKey {
        SigningKey::from_bytes(self.signing_seed.as_array())
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key().verifying_key()
    }

    pub fn public_bundle(&self) -> OperatorPublicBundle {
        OperatorPublicBundle {
            callsign: self.callsign.clone(),
            pq_ek: self.pq_keypair.ek,
            ed25519_vk: self.verifying_key().to_bytes(),
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(IDENTITY_SIZE);
        out.extend_from_slice(&IDENTITY_MAGIC);
        out.extend_from_slice(&encode_callsign(&self.callsign));
        out.extend_from_slice(&self.pq_keypair.ek);
        out.extend_from_slice(self.pq_keypair.dk.as_slice());
        out.extend_from_slice(self.signing_seed.as_slice());
        out
    }

    pub fn from_bytes(raw: &[u8]) -> Result<Self> {
        if raw.len() != IDENTITY_SIZE || raw[0..8] != IDENTITY_MAGIC {
            return Err(CryptoError::PostQuantumError(
                "invalid operator identity file format".into(),
            ));
        }
        let callsign = decode_callsign(&raw[8..8 + CALLSIGN_MAX_BYTES])?;

        let ek_off = 8 + CALLSIGN_MAX_BYTES;
        let mut ek = [0u8; PQ_EK_SIZE];
        ek.copy_from_slice(&raw[ek_off..ek_off + PQ_EK_SIZE]);

        let dk_off = ek_off + PQ_EK_SIZE;
        let dk = SecureArray::<PQ_DK_SIZE>::from_slice(&raw[dk_off..dk_off + PQ_DK_SIZE])
            .ok_or_else(|| CryptoError::PostQuantumError("bad identity PQ secret key".into()))?;

        let seed_off = dk_off + PQ_DK_SIZE;
        let signing_seed = SecureArray::<32>::from_slice(&raw[seed_off..seed_off + 32])
            .ok_or_else(|| CryptoError::PostQuantumError("bad identity Ed25519 seed".into()))?;

        Ok(Self {
            callsign,
            pq_keypair: PqKeypair { ek, dk },
            signing_seed,
        })
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct SealedDropMeta {
    pub filename: String,
    pub payload_bytes: usize,
    pub package_bytes: usize,
    pub sender_ed25519_hex: String,
    pub recipient_fingerprint: String,
    pub created_at_unix: u64,
    pub opsec_sanitized: bool,
    pub sender_pinned_match: bool,
}

pub struct UnsealedDrop {
    pub meta: SealedDropMeta,
    pub plaintext: Vec<u8>,
}

impl Drop for UnsealedDrop {
    fn drop(&mut self) {
        self.plaintext.zeroize();
    }
}

/// Seals `plaintext` into a post-quantum ML-KEM-1024 + AES-256-GCM + Ed25519 `.flcpack` drop.
/// Only the recipient's public bundle is required; no shared passphrase is exchanged.
pub fn seal_package(
    sender: &OperatorIdentity,
    recipient: &OperatorPublicBundle,
    filename: &str,
    plaintext: &[u8],
    opsec_sanitize: bool,
) -> Result<(Vec<u8>, SealedDropMeta, Option<SanitizeReport>)> {
    let clean_name = sanitize_filename(filename);
    let name_bytes = clean_name.as_bytes();
    if name_bytes.is_empty() || name_bytes.len() > MAX_FILENAME_BYTES {
        return Err(CryptoError::PostQuantumError(
            "drop filename must be 1..=255 bytes".into(),
        ));
    }

    let (mut working_pt, san_report) = if opsec_sanitize {
        let (clean, rep) = sanitize_file_bytes(plaintext);
        (clean, Some(rep))
    } else {
        (plaintext.to_vec(), None)
    };

    // Frame plaintext as: filename_len (u16 LE) || filename_utf8 || payload
    let mut framed = Vec::with_capacity(2 + name_bytes.len() + working_pt.len());
    framed.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
    framed.extend_from_slice(name_bytes);
    framed.extend_from_slice(&working_pt);
    let payload_bytes = working_pt.len();
    working_pt.zeroize();

    let (pq_ct, pq_ss) = pq_encapsulate(&recipient.pq_ek)?;
    let salt = random_bytes::<32>();
    let nonce_bytes = random_bytes::<12>();
    let cek = derive_drop_cek(&pq_ss, &salt)?;

    let created_at_unix = if opsec_sanitize { 0 } else { unix_now() };
    let flags = if opsec_sanitize {
        SEAL_FLAG_SANITIZED
    } else {
        0
    };
    let sender_vk = sender.verifying_key().to_bytes();
    let recipient_hash = recipient.key_hash();

    // Ciphertext length = framed.len() + 16-byte GCM tag
    let expected_ct_len = (framed.len() as u64)
        .checked_add(16)
        .ok_or(CryptoError::WrapFailed)?;

    let mut pkg = Vec::with_capacity(SEAL_HEADER_SIZE + (expected_ct_len as usize) + SEAL_SIG_SIZE);
    pkg.extend_from_slice(&SEAL_MAGIC);
    pkg.extend_from_slice(&SEAL_VERSION.to_le_bytes());
    pkg.extend_from_slice(&flags.to_le_bytes());
    pkg.extend_from_slice(&created_at_unix.to_le_bytes());
    pkg.extend_from_slice(&sender_vk);
    pkg.extend_from_slice(&recipient_hash);
    pkg.extend_from_slice(&salt);
    pkg.extend_from_slice(&nonce_bytes);
    pkg.extend_from_slice(&pq_ct);
    pkg.extend_from_slice(&expected_ct_len.to_le_bytes());
    debug_assert_eq!(pkg.len(), SEAL_HEADER_SIZE);

    let cipher = Aes256Gcm::new_from_slice(cek.as_slice()).map_err(|_| CryptoError::WrapFailed)?;
    let ct = cipher
        .encrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload {
                msg: &framed,
                aad: &pkg[..SEAL_HEADER_SIZE],
            },
        )
        .map_err(|_| CryptoError::WrapFailed)?;
    framed.zeroize();

    if ct.len() as u64 != expected_ct_len {
        return Err(CryptoError::WrapFailed);
    }
    pkg.extend_from_slice(&ct);

    // Sign BLAKE3 digest of header + ciphertext with sender's Ed25519 key.
    let digest = seal_signature_digest(&pkg);
    let sig: Signature = sender.signing_key().sign(&digest);
    pkg.extend_from_slice(&sig.to_bytes());

    let meta = SealedDropMeta {
        filename: clean_name,
        payload_bytes,
        package_bytes: pkg.len(),
        sender_ed25519_hex: hex::encode(sender_vk),
        recipient_fingerprint: recipient.fingerprint_hex(),
        created_at_unix,
        opsec_sanitized: opsec_sanitize,
        sender_pinned_match: true,
    };

    Ok((pkg, meta, san_report))
}

/// Verifies Ed25519 signature BEFORE decrypting, then ML-KEM-1024 decapsulates and AES-GCM decrypts.
pub fn unseal_package(
    recipient: &OperatorIdentity,
    expected_sender: Option<&OperatorPublicBundle>,
    package: &[u8],
) -> Result<UnsealedDrop> {
    let min_len = SEAL_HEADER_SIZE + 16 + SEAL_SIG_SIZE;
    if package.len() < min_len || package[0..8] != SEAL_MAGIC {
        return Err(CryptoError::IntegrityCheckFailed);
    }

    let version = u32::from_le_bytes(package[8..12].try_into().unwrap());
    if version != SEAL_VERSION {
        return Err(CryptoError::PostQuantumError(format!(
            "unsupported sealed drop version {version}"
        )));
    }
    let flags = u32::from_le_bytes(package[12..16].try_into().unwrap());
    let created_at_unix = u64::from_le_bytes(package[16..24].try_into().unwrap());

    let mut sender_vk_bytes = [0u8; 32];
    sender_vk_bytes.copy_from_slice(&package[24..56]);

    let mut recipient_hash = [0u8; 32];
    recipient_hash.copy_from_slice(&package[56..88]);

    let mut salt = [0u8; 32];
    salt.copy_from_slice(&package[88..120]);

    let mut nonce_bytes = [0u8; 12];
    nonce_bytes.copy_from_slice(&package[120..132]);

    let mut pq_ct = [0u8; PQ_CT_SIZE];
    pq_ct.copy_from_slice(&package[132..132 + PQ_CT_SIZE]);

    let ct_len_u64 = u64::from_le_bytes(package[1700..1708].try_into().unwrap());
    let ct_len = usize::try_from(ct_len_u64).map_err(|_| CryptoError::IntegrityCheckFailed)?;
    let signed_end = SEAL_HEADER_SIZE
        .checked_add(ct_len)
        .ok_or(CryptoError::IntegrityCheckFailed)?;
    let expected_total = signed_end
        .checked_add(SEAL_SIG_SIZE)
        .ok_or(CryptoError::IntegrityCheckFailed)?;
    if ct_len < 16 || package.len() != expected_total {
        return Err(CryptoError::IntegrityCheckFailed);
    }

    // 1. Verify sender Ed25519 signature BEFORE touching decapsulation or decryption.
    let sender_vk = VerifyingKey::from_bytes(&sender_vk_bytes)
        .map_err(|_| CryptoError::IntegrityCheckFailed)?;
    let mut sig_bytes = [0u8; SEAL_SIG_SIZE];
    sig_bytes.copy_from_slice(&package[signed_end..expected_total]);
    let sig = Signature::from_bytes(&sig_bytes);
    let digest = seal_signature_digest(&package[..signed_end]);
    sender_vk
        .verify(&digest, &sig)
        .map_err(|_| CryptoError::IntegrityCheckFailed)?;

    // 2. Enforce optional pinned sender identity check (constant-time).
    let sender_pinned_match = match expected_sender {
        Some(exp) => {
            if !bool::from(exp.ed25519_vk.ct_eq(&sender_vk_bytes)) {
                return Err(CryptoError::IntegrityCheckFailed);
            }
            true
        }
        None => false,
    };

    // 3. Check recipient fingerprint matches our identity.
    let my_pub = recipient.public_bundle();
    if !bool::from(my_pub.key_hash().ct_eq(&recipient_hash)) {
        return Err(CryptoError::UnwrapFailed);
    }

    // 4. ML-KEM-1024 decapsulate + HKDF-SHA512 + AES-256-GCM decrypt with header AAD.
    let pq_ss = pq_decapsulate(&recipient.pq_keypair.dk, &pq_ct)?;
    let cek = derive_drop_cek(&pq_ss, &salt)?;
    let cipher =
        Aes256Gcm::new_from_slice(cek.as_slice()).map_err(|_| CryptoError::UnwrapFailed)?;
    let mut framed = cipher
        .decrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload {
                msg: &package[SEAL_HEADER_SIZE..signed_end],
                aad: &package[..SEAL_HEADER_SIZE],
            },
        )
        .map_err(|_| CryptoError::UnwrapFailed)?;

    if framed.len() < 2 {
        framed.zeroize();
        return Err(CryptoError::IntegrityCheckFailed);
    }
    let name_len = u16::from_le_bytes([framed[0], framed[1]]) as usize;
    if name_len == 0 || name_len > MAX_FILENAME_BYTES || 2 + name_len > framed.len() {
        framed.zeroize();
        return Err(CryptoError::IntegrityCheckFailed);
    }
    let raw_name = std::str::from_utf8(&framed[2..2 + name_len])
        .map_err(|_| CryptoError::IntegrityCheckFailed)?;
    let filename = sanitize_filename(raw_name);
    let plaintext = framed[2 + name_len..].to_vec();
    framed.zeroize();

    let meta = SealedDropMeta {
        filename,
        payload_bytes: plaintext.len(),
        package_bytes: package.len(),
        sender_ed25519_hex: hex::encode(sender_vk_bytes),
        recipient_fingerprint: my_pub.fingerprint_hex(),
        created_at_unix,
        opsec_sanitized: (flags & SEAL_FLAG_SANITIZED) != 0,
        sender_pinned_match,
    };

    Ok(UnsealedDrop { meta, plaintext })
}

fn derive_drop_cek(pq_ss: &SecureArray<32>, salt: &[u8; 32]) -> Result<SecureArray<32>> {
    let hk = Hkdf::<Sha512>::new(Some(salt), pq_ss.as_slice());
    let mut cek = SecureArray::<32>::zeroed();
    hk.expand(SEAL_CEK_INFO, cek.as_array_mut())
        .map_err(|_| CryptoError::HkdfFailed)?;
    Ok(cek)
}

fn seal_signature_digest(signed_region: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(SEAL_SIG_DOMAIN);
    h.update(signed_region);
    *h.finalize().as_bytes()
}

fn encode_callsign(s: &str) -> [u8; CALLSIGN_MAX_BYTES] {
    let clean = sanitize_callsign(s);
    let mut buf = [0u8; CALLSIGN_MAX_BYTES];
    let bytes = clean.as_bytes();
    let n = bytes.len().min(CALLSIGN_MAX_BYTES);
    buf[..n].copy_from_slice(&bytes[..n]);
    buf
}

fn decode_callsign(raw: &[u8]) -> Result<String> {
    let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
    let s = std::str::from_utf8(&raw[..end])
        .map_err(|_| CryptoError::PostQuantumError("invalid UTF-8 callsign".into()))?;
    Ok(s.to_string())
}

fn sanitize_callsign(s: &str) -> String {
    let mut out = String::new();
    for ch in s.trim().chars() {
        if !ch.is_control() {
            if out.len() + ch.len_utf8() > CALLSIGN_MAX_BYTES {
                break;
            }
            out.push(ch);
        }
    }
    if out.is_empty() {
        "OPERATOR".to_string()
    } else {
        out
    }
}

fn sanitize_filename(name: &str) -> String {
    let base = name.rsplit(['/', '\\']).next().unwrap_or("drop.bin").trim();
    let cleaned: String = base
        .chars()
        .filter(|c| !c.is_control() && *c != '/' && *c != '\\')
        .collect();
    if cleaned.is_empty() || cleaned == "." || cleaned == ".." {
        "drop.bin".to_string()
    } else {
        cleaned
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

    #[test]
    fn sealed_drop_round_trip_and_tamper_rejection() {
        let alpha = OperatorIdentity::generate("ALPHA-1");
        let bravo = OperatorIdentity::generate("BRAVO-2");

        // Round-trip serialization of identity & public bundle
        let alpha_loaded = OperatorIdentity::from_bytes(&alpha.to_bytes()).unwrap();
        let bravo_pub =
            OperatorPublicBundle::from_bytes(&bravo.public_bundle().to_bytes()).unwrap();
        let alpha_pub =
            OperatorPublicBundle::from_bytes(&alpha.public_bundle().to_bytes()).unwrap();

        assert_eq!(alpha_loaded.callsign, "ALPHA-1");
        assert_eq!(bravo_pub.callsign, "BRAVO-2");

        let secret = b"TOP-SECRET GRID 37.9838N 23.7275E";
        let (mut pkg, meta, _) =
            seal_package(&alpha_loaded, &bravo_pub, "ops/sitrep.txt", secret, false).unwrap();
        assert_eq!(meta.filename, "sitrep.txt");

        // Bravo unseals and verifies pinned sender Alpha
        let drop = unseal_package(&bravo, Some(&alpha_pub), &pkg).unwrap();
        assert_eq!(drop.meta.filename, "sitrep.txt");
        assert_eq!(drop.plaintext.as_slice(), secret);
        assert!(drop.meta.sender_pinned_match);

        // Wrong recipient rejected
        assert!(unseal_package(&alpha, None, &pkg).is_err());

        // Wrong pinned sender rejected
        assert!(unseal_package(&bravo, Some(&bravo_pub), &pkg).is_err());

        // Any 1-bit flip in ciphertext or signature rejected
        let mid = pkg.len() / 2;
        pkg[mid] ^= 0x01;
        assert!(unseal_package(&bravo, Some(&alpha_pub), &pkg).is_err());
    }
}
