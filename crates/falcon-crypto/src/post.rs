use crate::custody::{create_signed_entry, verify_custody_chain};
use crate::error::{CryptoError, Result};
use crate::integrity::{compute_sector_tag, verify_sector_tag};
use crate::memory::SecureArray;
use crate::pq::{combine_hybrid_kek, pq_decapsulate, pq_encapsulate, PqKeypair};
use crate::seal::{seal_package, unseal_package, OperatorIdentity};
use crate::shamir::{combine_shares, split_secret};
use crate::wrap::{unwrap_master_secret, wrap_master_secret, MASTER_SECRET_SIZE};
use crate::xts::{XtsCipher, SECTOR_SIZE};
use aes::cipher::KeyInit;
use aes::Aes256;
use ed25519_dalek::SigningKey;
use serde::Serialize;
use std::time::Instant;
use xts_mode::{get_tweak_default, Xts128};

#[derive(Debug, Clone, Serialize)]
pub struct PostCheck {
    pub name: &'static str,
    pub standard: &'static str,
    pub passed: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct PostReport {
    pub passed: bool,
    pub duration_ms: f64,
    pub checks: Vec<PostCheck>,
}

/// FIPS 140-3 style Power-On Self-Test (POST).
/// Runs Known-Answer Tests & pairwise consistency checks across every active primitive.
/// Any failure returns `Err` so the caller fails closed before touching keys or storage.
pub fn run_power_on_self_test() -> Result<PostReport> {
    let t0 = Instant::now();
    let mut checks = Vec::with_capacity(7);

    let c1 = check_aes_xts_kat();
    checks.push(PostCheck {
        name: "AES-256-XTS KAT (Vector 10)",
        standard: "IEEE P1619 / NIST SP 800-38E",
        passed: c1,
    });

    let c2 = check_cascade_serpent();
    checks.push(PostCheck {
        name: "Cascade AES-256 + Serpent-256",
        standard: "Dual-Cipher XTS Round-Trip",
        passed: c2,
    });

    let c3 = check_blake3_mac();
    checks.push(PostCheck {
        name: "BLAKE3-256 Encrypt-then-MAC",
        standard: "Keyed MAC + Tamper Rejection",
        passed: c3,
    });

    let c4 = check_aes_gcm_wrap();
    checks.push(PostCheck {
        name: "AES-256-GCM Key Wrap + AAD",
        standard: "NIST SP 800-38D",
        passed: c4,
    });

    let c5 = check_ml_kem_1024();
    checks.push(PostCheck {
        name: "ML-KEM-1024 Hybrid KEM",
        standard: "FIPS 203 / CNSA 2.0",
        passed: c5,
    });

    let c6 = check_shamir_and_ed25519();
    checks.push(PostCheck {
        name: "Shamir GF(256) + Ed25519 Custody",
        standard: "RFC 8032 / Threshold 3-of-5",
        passed: c6,
    });

    let c7 = check_sealed_drop();
    checks.push(PostCheck {
        name: "Sealed Drop (ML-KEM + Ed25519)",
        standard: "FIPS 203 + AES-256-GCM + RFC 8032",
        passed: c7,
    });

    let all_ok = checks.iter().all(|c| c.passed);
    let report = PostReport {
        passed: all_ok,
        duration_ms: t0.elapsed().as_secs_f64() * 1000.0,
        checks,
    };

    if all_ok {
        Ok(report)
    } else {
        Err(CryptoError::IntegrityCheckFailed)
    }
}

fn check_aes_xts_kat() -> bool {
    let k1: [u8; 32] = [
        0x27, 0x18, 0x28, 0x18, 0x28, 0x45, 0x90, 0x45, 0x23, 0x53, 0x60, 0x28, 0x74, 0x71, 0x35,
        0x26, 0x62, 0x49, 0x77, 0x57, 0x24, 0x70, 0x93, 0x69, 0x99, 0x59, 0x57, 0x49, 0x66, 0x96,
        0x76, 0x27,
    ];
    let k2: [u8; 32] = [
        0x31, 0x41, 0x59, 0x26, 0x53, 0x58, 0x97, 0x93, 0x23, 0x84, 0x62, 0x64, 0x33, 0x83, 0x27,
        0x95, 0x02, 0x88, 0x41, 0x97, 0x16, 0x93, 0x99, 0x37, 0x51, 0x05, 0x82, 0x09, 0x74, 0x94,
        0x45, 0x92,
    ];
    let pt: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ];
    let expected: [u8; 32] = [
        0x1c, 0x3b, 0x3a, 0x10, 0x2f, 0x77, 0x03, 0x86, 0xe4, 0x83, 0x6c, 0x99, 0xe3, 0x70, 0xcf,
        0x9b, 0xea, 0x00, 0x80, 0x3f, 0x5e, 0x48, 0x23, 0x57, 0xa4, 0xae, 0x12, 0xd4, 0x14, 0xa3,
        0xe6, 0x3b,
    ];

    let Ok(c1) = Aes256::new_from_slice(&k1) else {
        return false;
    };
    let Ok(c2) = Aes256::new_from_slice(&k2) else {
        return false;
    };
    let xts = Xts128::new(c1, c2);
    let mut buf = pt;
    xts.encrypt_sector(&mut buf, get_tweak_default(0xff));
    if buf != expected {
        return false;
    }
    xts.decrypt_sector(&mut buf, get_tweak_default(0xff));
    buf == pt
}

fn check_cascade_serpent() -> bool {
    let Ok(cas) = XtsCipher::new_cascade(&[1u8; 32], &[2u8; 32], &[3u8; 32], &[4u8; 32]) else {
        return false;
    };
    let orig = [0x3Cu8; SECTOR_SIZE];
    let mut buf = orig;
    if cas.encrypt_sector(42, &mut buf).is_err() || buf == orig {
        return false;
    }
    cas.decrypt_sector(42, &mut buf).is_ok() && buf == orig
}

fn check_blake3_mac() -> bool {
    let key = [0x61u8; 32];
    let uuid = [0x72u8; 16];
    let mut ct = [0x83u8; 64];
    let tag = compute_sector_tag(&key, &uuid, 3, &ct);
    if verify_sector_tag(&key, &uuid, 3, &ct, &tag).is_err() {
        return false;
    }
    ct[0] ^= 0x01;
    verify_sector_tag(&key, &uuid, 3, &ct, &tag).is_err()
}

fn check_aes_gcm_wrap() -> bool {
    let Some(kek) = SecureArray::<32>::from_slice(&[0x19u8; 32]) else {
        return false;
    };
    let Some(secret) = SecureArray::<MASTER_SECRET_SIZE>::from_slice(&[0x5Au8; MASTER_SECRET_SIZE])
    else {
        return false;
    };
    let nonce = [0x07u8; 12];
    let Ok(wrapped) = wrap_master_secret(&kek, &nonce, b"post-aad", &secret) else {
        return false;
    };
    let Ok(unwrapped) = unwrap_master_secret(&kek, &nonce, b"post-aad", &wrapped) else {
        return false;
    };
    unwrapped.ct_eq(&secret) && unwrap_master_secret(&kek, &nonce, b"bad-aad", &wrapped).is_err()
}

fn check_ml_kem_1024() -> bool {
    let kp = PqKeypair::generate();
    let Ok((ct, ss1)) = pq_encapsulate(&kp.ek) else {
        return false;
    };
    let Ok(ss2) = pq_decapsulate(&kp.dk, &ct) else {
        return false;
    };
    let Some(kek) = SecureArray::<32>::from_slice(&[0x44u8; 32]) else {
        return false;
    };
    let salt = [0x21u8; 32];
    let Ok(h1) = combine_hybrid_kek(&kek, &ss1, &salt) else {
        return false;
    };
    let Ok(h2) = combine_hybrid_kek(&kek, &ss2, &salt) else {
        return false;
    };
    ss1.ct_eq(&ss2) && h1.ct_eq(&h2)
}

fn check_shamir_and_ed25519() -> bool {
    let secret = [0xA7u8; 32];
    let Ok(shares) = split_secret(&secret, 3, 5) else {
        return false;
    };
    let Ok(rec) = combine_shares(&[shares[0].clone(), shares[2].clone(), shares[4].clone()]) else {
        return false;
    };
    if rec.as_slice() != secret {
        return false;
    }

    let sk = SigningKey::from_bytes(&[0x31u8; 32]);
    let vk = sk.verifying_key();
    let e = create_signed_entry(&sk, None, "POST", 0, "self-test");
    verify_custody_chain(&[e], &vk).valid
}

fn check_sealed_drop() -> bool {
    let sender = OperatorIdentity::generate("POST-TX");
    let recipient = OperatorIdentity::generate("POST-RX");
    let r_pub = recipient.public_bundle();
    let s_pub = sender.public_bundle();
    let Ok((mut pkg, _, _)) = seal_package(&sender, &r_pub, "kat.bin", b"falcon-post-kat", false)
    else {
        return false;
    };
    let Ok(drop) = unseal_package(&recipient, Some(&s_pub), &pkg) else {
        return false;
    };
    if drop.plaintext != b"falcon-post-kat" || !drop.meta.sender_pinned_match {
        return false;
    }
    let last = pkg.len() - 1;
    pkg[last] ^= 0x80;
    unseal_package(&recipient, Some(&s_pub), &pkg).is_err()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn post_passes_all_seven_checks() {
        let rep = run_power_on_self_test().unwrap();
        assert!(rep.passed);
        assert_eq!(rep.checks.len(), 7);
    }
}
