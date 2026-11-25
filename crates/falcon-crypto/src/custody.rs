use crate::error::{CryptoError, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

const CUSTODY_HASH_DOMAIN: &[u8] = b"falcon-v3-custody-entry";
pub const GENESIS_PREV_HASH: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CustodyEntry {
    pub seq: u64,
    pub timestamp_utc: u64,
    pub event: String,
    pub slot: usize,
    pub detail: String,
    pub prev_hash: String,
    pub entry_hash: String,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct CustodyVerifyReport {
    pub valid: bool,
    pub entry_count: usize,
    pub pubkey_hex: String,
    pub head_hash: String,
    pub broken_at_seq: Option<u64>,
    pub reason: Option<String>,
}

pub fn compute_entry_hash(
    seq: u64,
    timestamp_utc: u64,
    event: &str,
    slot: usize,
    detail: &str,
    prev_hash: &str,
) -> String {
    let mut h = blake3::Hasher::new();
    h.update(CUSTODY_HASH_DOMAIN);
    h.update(&seq.to_le_bytes());
    h.update(&timestamp_utc.to_le_bytes());
    h.update(&(event.len() as u64).to_le_bytes());
    h.update(event.as_bytes());
    h.update(&(slot as u64).to_le_bytes());
    h.update(&(detail.len() as u64).to_le_bytes());
    h.update(detail.as_bytes());
    h.update(prev_hash.as_bytes());
    hex::encode(h.finalize().as_bytes())
}

pub fn create_signed_entry(
    signing_key: &SigningKey,
    prev: Option<&CustodyEntry>,
    event: &str,
    slot: usize,
    detail: &str,
) -> CustodyEntry {
    let seq = prev.map(|p| p.seq + 1).unwrap_or(1);
    let prev_hash = prev
        .map(|p| p.entry_hash.clone())
        .unwrap_or_else(|| GENESIS_PREV_HASH.to_string());
    let timestamp_utc = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let entry_hash = compute_entry_hash(seq, timestamp_utc, event, slot, detail, &prev_hash);
    let sig: Signature = signing_key.sign(entry_hash.as_bytes());

    CustodyEntry {
        seq,
        timestamp_utc,
        event: event.to_string(),
        slot,
        detail: detail.to_string(),
        prev_hash,
        entry_hash,
        signature: hex::encode(sig.to_bytes()),
    }
}

pub fn parse_custody_jsonl(raw: &str) -> Result<Vec<CustodyEntry>> {
    let mut entries = Vec::new();
    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let entry: CustodyEntry =
            serde_json::from_str(trimmed).map_err(|_| CryptoError::IntegrityCheckFailed)?;
        entries.push(entry);
    }
    Ok(entries)
}

pub fn encode_custody_jsonl(entries: &[CustodyEntry]) -> String {
    let mut out = String::new();
    for e in entries {
        if let Ok(line) = serde_json::to_string(e) {
            out.push_str(&line);
            out.push('\n');
        }
    }
    out
}

pub fn verify_custody_chain(
    entries: &[CustodyEntry],
    verifying_key: &VerifyingKey,
) -> CustodyVerifyReport {
    let pubkey_hex = hex::encode(verifying_key.as_bytes());
    let mut expected_prev = GENESIS_PREV_HASH.to_string();

    for (expected_seq, e) in (1u64..).zip(entries.iter()) {
        if e.seq != expected_seq {
            return CustodyVerifyReport {
                valid: false,
                entry_count: entries.len(),
                pubkey_hex,
                head_hash: expected_prev,
                broken_at_seq: Some(e.seq),
                reason: Some(format!("expected seq {expected_seq}, got {}", e.seq)),
            };
        }
        if e.prev_hash != expected_prev {
            return CustodyVerifyReport {
                valid: false,
                entry_count: entries.len(),
                pubkey_hex,
                head_hash: expected_prev,
                broken_at_seq: Some(e.seq),
                reason: Some("broken hash chain link".into()),
            };
        }

        let recomputed = compute_entry_hash(
            e.seq,
            e.timestamp_utc,
            &e.event,
            e.slot,
            &e.detail,
            &e.prev_hash,
        );
        if recomputed != e.entry_hash {
            return CustodyVerifyReport {
                valid: false,
                entry_count: entries.len(),
                pubkey_hex,
                head_hash: expected_prev,
                broken_at_seq: Some(e.seq),
                reason: Some("entry hash mismatch (modified record)".into()),
            };
        }

        let sig_bytes = match hex::decode(&e.signature) {
            Ok(b) if b.len() == 64 => b,
            _ => {
                return CustodyVerifyReport {
                    valid: false,
                    entry_count: entries.len(),
                    pubkey_hex,
                    head_hash: expected_prev,
                    broken_at_seq: Some(e.seq),
                    reason: Some("malformed Ed25519 signature".into()),
                }
            }
        };
        let sig_arr: [u8; 64] = sig_bytes.try_into().unwrap();
        let sig = Signature::from_bytes(&sig_arr);

        if verifying_key.verify(e.entry_hash.as_bytes(), &sig).is_err() {
            return CustodyVerifyReport {
                valid: false,
                entry_count: entries.len(),
                pubkey_hex,
                head_hash: expected_prev,
                broken_at_seq: Some(e.seq),
                reason: Some("Ed25519 signature verification failed".into()),
            };
        }

        expected_prev = e.entry_hash.clone();
    }

    CustodyVerifyReport {
        valid: true,
        entry_count: entries.len(),
        pubkey_hex,
        head_hash: expected_prev,
        broken_at_seq: None,
        reason: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn custody_chain_verifies_and_catches_tampering() {
        let sk = SigningKey::from_bytes(&[0x55u8; 32]);
        let vk = sk.verifying_key();

        let e1 = create_signed_entry(&sk, None, "CREATE", 0, "volume initialized");
        let e2 = create_signed_entry(&sk, Some(&e1), "PUT", 0, "ops/plan.pdf");
        let mut chain = vec![e1, e2];

        let rep = verify_custody_chain(&chain, &vk);
        assert!(rep.valid);
        assert_eq!(rep.entry_count, 2);

        // Altering a detail breaks hash + signature
        chain[0].detail = "forged".to_string();
        let bad = verify_custody_chain(&chain, &vk);
        assert!(!bad.valid);
        assert_eq!(bad.broken_at_seq, Some(1));
    }
}
