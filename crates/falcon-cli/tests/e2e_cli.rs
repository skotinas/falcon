use std::fs::{self, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::process::Command;

fn falcon_bin() -> &'static str {
    env!("CARGO_BIN_EXE_falcon")
}

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("falcon_e2e_{}_{}", std::process::id(), name));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn full_cli_lifecycle() {
    let dir = temp_dir("lifecycle");
    let keyfile = dir.join("drive.key");
    let vault = dir.join("data.flc");
    let src_file = dir.join("sample.bin");
    let out_file = dir.join("recovered.bin");
    let hdr_bak = dir.join("data.hdr.bak");

    let mut payload = b"falcon-plaintext-sentinel-0123456789".to_vec();
    for i in 0..131_072usize {
        payload.push(((i * 73 + 17) & 0xFF) as u8);
    }
    fs::write(&src_file, &payload).unwrap();

    assert!(Command::new(falcon_bin())
        .args(["keygen", keyfile.to_str().unwrap(), "--bytes", "64"])
        .status()
        .unwrap()
        .success());
    assert_eq!(fs::metadata(&keyfile).unwrap().len(), 64);

    assert!(Command::new(falcon_bin())
        .env("FALCON_PW", "correct-horse-99!")
        .args([
            "create",
            vault.to_str().unwrap(),
            "--size",
            "1M",
            "--profile",
            "fast-test",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "--passphrase-env",
            "FALCON_PW",
        ])
        .status()
        .unwrap()
        .success());

    let info = Command::new(falcon_bin())
        .args(["info", vault.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(info.status.success());
    let stdout = String::from_utf8_lossy(&info.stdout);
    assert!(stdout.contains("AES-256-XTS"));
    assert!(stdout.contains("BLAKE3-256 enabled"));
    assert!(stdout.contains("keyfile=yes"));

    assert!(Command::new(falcon_bin())
        .env("FALCON_PW", "correct-horse-99!")
        .args([
            "put",
            vault.to_str().unwrap(),
            src_file.to_str().unwrap(),
            "docs/sample.bin",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "--passphrase-env",
            "FALCON_PW",
        ])
        .status()
        .unwrap()
        .success());

    let raw_vault = fs::read(&vault).unwrap();
    assert!(!raw_vault
        .windows(24)
        .any(|w| w == b"falcon-plaintext-sentine"));

    let ls = Command::new(falcon_bin())
        .env("FALCON_PW", "correct-horse-99!")
        .args([
            "ls",
            vault.to_str().unwrap(),
            "--keyfile",
            keyfile.to_str().unwrap(),
            "--passphrase-env",
            "FALCON_PW",
        ])
        .output()
        .unwrap();
    assert!(ls.status.success());
    assert!(String::from_utf8_lossy(&ls.stdout).contains("docs/sample.bin"));

    assert!(Command::new(falcon_bin())
        .env("FALCON_PW", "correct-horse-99!")
        .args([
            "get",
            vault.to_str().unwrap(),
            "docs/sample.bin",
            out_file.to_str().unwrap(),
            "--keyfile",
            keyfile.to_str().unwrap(),
            "--passphrase-env",
            "FALCON_PW",
        ])
        .status()
        .unwrap()
        .success());
    assert_eq!(fs::read(&out_file).unwrap(), payload);

    assert!(Command::new(falcon_bin())
        .env("FALCON_PW", "correct-horse-99!")
        .args([
            "verify",
            vault.to_str().unwrap(),
            "--keyfile",
            keyfile.to_str().unwrap(),
            "--passphrase-env",
            "FALCON_PW",
        ])
        .status()
        .unwrap()
        .success());

    assert!(Command::new(falcon_bin())
        .env("FALCON_PW", "correct-horse-99!")
        .env("FALCON_REC", "recovery-pass-42!")
        .args([
            "keyslot",
            "add",
            vault.to_str().unwrap(),
            "--label",
            "recovery",
            "--profile",
            "fast-test",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "--passphrase-env",
            "FALCON_PW",
            "--new-passphrase-env",
            "FALCON_REC",
        ])
        .status()
        .unwrap()
        .success());

    assert!(Command::new(falcon_bin())
        .args([
            "header",
            "backup",
            vault.to_str().unwrap(),
            hdr_bak.to_str().unwrap(),
        ])
        .status()
        .unwrap()
        .success());

    // Damage primary header and make sure repair recovers cleanly from backup.
    {
        let mut f = OpenOptions::new().write(true).open(&vault).unwrap();
        f.seek(SeekFrom::Start(0)).unwrap();
        f.write_all(&[0xDEu8; 128]).unwrap();
        f.sync_all().unwrap();
    }

    assert!(Command::new(falcon_bin())
        .env("FALCON_REC", "recovery-pass-42!")
        .args([
            "header",
            "repair",
            vault.to_str().unwrap(),
            "--passphrase-env",
            "FALCON_REC",
        ])
        .status()
        .unwrap()
        .success());

    assert!(Command::new(falcon_bin())
        .env("FALCON_REC", "recovery-pass-42!")
        .args([
            "verify",
            vault.to_str().unwrap(),
            "--passphrase-env",
            "FALCON_REC",
        ])
        .status()
        .unwrap()
        .success());

    // Flip 1 bit in data region and verify tamper detection triggers.
    {
        let mut f = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&vault)
            .unwrap();
        f.seek(SeekFrom::Start(64 * 1024)).unwrap();
        let mut b = [0u8; 1];
        f.read_exact(&mut b).unwrap();
        b[0] ^= 0x01;
        f.seek(SeekFrom::Start(64 * 1024)).unwrap();
        f.write_all(&b).unwrap();
        f.sync_all().unwrap();
    }

    let tamper = Command::new(falcon_bin())
        .env("FALCON_REC", "recovery-pass-42!")
        .args([
            "verify",
            vault.to_str().unwrap(),
            "--passphrase-env",
            "FALCON_REC",
        ])
        .output()
        .unwrap();
    assert!(!tamper.status.success());
    assert!(String::from_utf8_lossy(&tamper.stdout).contains("TAMPERING DETECTED"));

    // Shred destroys all access permanently.
    assert!(Command::new(falcon_bin())
        .args(["shred", vault.to_str().unwrap(), "--yes-destroy-forever"])
        .status()
        .unwrap()
        .success());

    let after = Command::new(falcon_bin())
        .env("FALCON_REC", "recovery-pass-42!")
        .args([
            "ls",
            vault.to_str().unwrap(),
            "--passphrase-env",
            "FALCON_REC",
        ])
        .status()
        .unwrap();
    assert!(!after.success());

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn ultimate_v2_cascade_pq_stealth_shamir_duress_diag() {
    let dir = temp_dir("ultimate_v2");
    let pq_key = dir.join("falcon.pqkey");
    let hdr = dir.join("stealth.fhdr");
    let vault = dir.join("noise.bin");
    let rec_key = dir.join("master.key");
    let comb_key = dir.join("reconstructed.key");
    let sample = dir.join("payload.bin");
    let extracted = dir.join("extracted.bin");

    fs::write(&sample, b"quantum-safe-cascade-stealth-payload-2026").unwrap();

    // 1. Generate FIPS 203 ML-KEM-1024 keypair
    assert!(Command::new(falcon_bin())
        .args(["pq-keygen", pq_key.to_str().unwrap()])
        .status()
        .unwrap()
        .success());

    // 2. Shamir 3-of-5 split a fresh recovery keyfile, then reconstruct from 3 shares
    let split_out = Command::new(falcon_bin())
        .args([
            "shamir",
            "split",
            "--threshold",
            "3",
            "--shares",
            "5",
            "--out-keyfile",
            rec_key.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(split_out.status.success());
    let share_lines: Vec<String> = String::from_utf8_lossy(&split_out.stdout)
        .lines()
        .filter_map(|l| {
            l.split("FLCN-S1-")
                .nth(1)
                .map(|rest| format!("FLCN-S1-{rest}"))
        })
        .collect();
    assert_eq!(share_lines.len(), 5);

    assert!(Command::new(falcon_bin())
        .args([
            "shamir",
            "combine",
            "--out",
            comb_key.to_str().unwrap(),
            &share_lines[0],
            &share_lines[2],
            &share_lines[4],
        ])
        .status()
        .unwrap()
        .success());
    assert_eq!(fs::read(&rec_key).unwrap(), fs::read(&comb_key).unwrap());

    // 3. Create Cascade AES+Serpent + ML-KEM-1024 PQ + Shamir Keyfile + Detached Stealth Header volume
    assert!(Command::new(falcon_bin())
        .env("FALCON_PW", "v2-master-pass!")
        .args([
            "create",
            vault.to_str().unwrap(),
            "--size",
            "512K",
            "--profile",
            "fast-test",
            "--cascade",
            "--header",
            hdr.to_str().unwrap(),
            "--keyfile",
            comb_key.to_str().unwrap(),
            "--pq-key",
            pq_key.to_str().unwrap(),
            "--passphrase-env",
            "FALCON_PW",
        ])
        .status()
        .unwrap()
        .success());

    // 4. Confirm zero FLCNDSK1 signature inside stealth volume via `diag`
    let diag = Command::new(falcon_bin())
        .args(["diag", vault.to_str().unwrap(), "--sectors", "256"])
        .output()
        .unwrap();
    assert!(diag.status.success());
    let diag_str = String::from_utf8_lossy(&diag.stdout);
    assert!(diag_str.contains("NO (stealth / detached"));

    // 5. Store & extract file through Cascade + PQ + Stealth
    assert!(Command::new(falcon_bin())
        .env("FALCON_PW", "v2-master-pass!")
        .args([
            "put",
            vault.to_str().unwrap(),
            sample.to_str().unwrap(),
            "doc.bin",
            "--header",
            hdr.to_str().unwrap(),
            "--keyfile",
            comb_key.to_str().unwrap(),
            "--pq-key",
            pq_key.to_str().unwrap(),
            "--passphrase-env",
            "FALCON_PW",
        ])
        .status()
        .unwrap()
        .success());

    assert!(Command::new(falcon_bin())
        .env("FALCON_PW", "v2-master-pass!")
        .args([
            "get",
            vault.to_str().unwrap(),
            "doc.bin",
            extracted.to_str().unwrap(),
            "--header",
            hdr.to_str().unwrap(),
            "--keyfile",
            comb_key.to_str().unwrap(),
            "--pq-key",
            pq_key.to_str().unwrap(),
            "--passphrase-env",
            "FALCON_PW",
        ])
        .status()
        .unwrap()
        .success());
    assert_eq!(fs::read(&extracted).unwrap(), fs::read(&sample).unwrap());

    // 6. Arm Duress password, trigger it -> silently shreds detached header & volume
    assert!(Command::new(falcon_bin())
        .env("FALCON_PW", "v2-master-pass!")
        .env("FALCON_DURESS", "red-button-000")
        .args([
            "duress",
            vault.to_str().unwrap(),
            "--profile",
            "fast-test",
            "--header",
            hdr.to_str().unwrap(),
            "--keyfile",
            comb_key.to_str().unwrap(),
            "--pq-key",
            pq_key.to_str().unwrap(),
            "--passphrase-env",
            "FALCON_PW",
            "--duress-passphrase-env",
            "FALCON_DURESS",
        ])
        .status()
        .unwrap()
        .success());

    // Trigger duress -> returns ordinary failure...
    let duress_run = Command::new(falcon_bin())
        .env("FALCON_DURESS", "red-button-000")
        .args([
            "ls",
            vault.to_str().unwrap(),
            "--header",
            hdr.to_str().unwrap(),
            "--passphrase-env",
            "FALCON_DURESS",
        ])
        .status()
        .unwrap();
    assert!(!duress_run.success());

    // ...and now even the real credentials can never open the volume!
    let real_after = Command::new(falcon_bin())
        .env("FALCON_PW", "v2-master-pass!")
        .args([
            "ls",
            vault.to_str().unwrap(),
            "--header",
            hdr.to_str().unwrap(),
            "--keyfile",
            comb_key.to_str().unwrap(),
            "--pq-key",
            pq_key.to_str().unwrap(),
            "--passphrase-env",
            "FALCON_PW",
        ])
        .status()
        .unwrap();
    assert!(!real_after.success());

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn comsec_v3_post_hidden_custody_sanitize_qr_and_dead_mans_switch() {
    let dir = temp_dir("comsec_v3");
    let vault = dir.join("decoy.flc");
    let jpg_in = dir.join("photo.jpg");
    let jpg_out = dir.join("photo_clean.jpg");
    let qr_dir = dir.join("keycards");

    // 1. FIPS 140-3 Power-On Self-Test
    let post = Command::new(falcon_bin()).args(["post"]).output().unwrap();
    assert!(post.status.success());
    assert!(String::from_utf8_lossy(&post.stdout).contains("POST): PASS"));

    // 2. Create 2 MiB outer decoy volume with Mission TTL (72h) & Dead-Man's Switch (3 strikes)
    assert!(Command::new(falcon_bin())
        .env("OUTER_PW", "decoy-pass-01")
        .args([
            "create",
            vault.to_str().unwrap(),
            "--size",
            "2M",
            "--profile",
            "fast-test",
            "--ttl-hours",
            "72",
            "--max-attempts",
            "3",
            "--passphrase-env",
            "OUTER_PW",
        ])
        .status()
        .unwrap()
        .success());

    // 3. Put a JPEG with embedded EXIF GPS coordinates using --sanitize -> GPS stripped!
    let mut fake_jpg = vec![0xFF, 0xD8];
    let exif = b"Exif\0\0GPS:37.9838N,23.7275E";
    fake_jpg.extend_from_slice(&[0xFF, 0xE1]);
    fake_jpg.extend_from_slice(&((exif.len() + 2) as u16).to_be_bytes());
    fake_jpg.extend_from_slice(exif);
    fake_jpg.extend_from_slice(&[0xFF, 0xDA, 0x00, 0x02, 0xAA, 0xBB, 0xFF, 0xD9]);
    fs::write(&jpg_in, &fake_jpg).unwrap();

    assert!(Command::new(falcon_bin())
        .env("OUTER_PW", "decoy-pass-01")
        .args([
            "put",
            vault.to_str().unwrap(),
            jpg_in.to_str().unwrap(),
            "decoy/photo.jpg",
            "--sanitize",
            "--passphrase-env",
            "OUTER_PW",
        ])
        .status()
        .unwrap()
        .success());

    assert!(Command::new(falcon_bin())
        .env("OUTER_PW", "decoy-pass-01")
        .args([
            "get",
            vault.to_str().unwrap(),
            "decoy/photo.jpg",
            jpg_out.to_str().unwrap(),
            "--passphrase-env",
            "OUTER_PW",
        ])
        .status()
        .unwrap()
        .success());
    let cleaned_jpg = fs::read(&jpg_out).unwrap();
    assert!(
        !cleaned_jpg.windows(3).any(|w| w == b"GPS"),
        "EXIF GPS was not stripped!"
    );

    // 4. Verify Ed25519 hash-chained Chain-of-Custody log
    let cust = Command::new(falcon_bin())
        .env("OUTER_PW", "decoy-pass-01")
        .args([
            "custody",
            "verify",
            vault.to_str().unwrap(),
            "--passphrase-env",
            "OUTER_PW",
        ])
        .output()
        .unwrap();
    assert!(cust.status.success());
    let cust_out = String::from_utf8_lossy(&cust.stdout);
    assert!(cust_out.contains("VALID (Ed25519 + BLAKE3 chain intact)"));
    assert!(cust_out.contains("PUT_SANITIZED"));

    // 5. Provision Plausible Deniability Hidden Volume inside outer decoy volume
    assert!(Command::new(falcon_bin())
        .env("OUTER_PW", "decoy-pass-01")
        .env("HIDDEN_PW", "classified-inner-99")
        .args([
            "hidden",
            "create",
            vault.to_str().unwrap(),
            "--profile",
            "fast-test",
            "--cascade",
            "--passphrase-env",
            "OUTER_PW",
            "--hidden-passphrase-env",
            "HIDDEN_PW",
        ])
        .status()
        .unwrap()
        .success());

    // Outer decoy volume STILL passes 100% full integrity verification!
    assert!(Command::new(falcon_bin())
        .env("OUTER_PW", "decoy-pass-01")
        .args([
            "verify",
            vault.to_str().unwrap(),
            "--passphrase-env",
            "OUTER_PW",
        ])
        .status()
        .unwrap()
        .success());

    // Store & verify a secret inside the Hidden Volume using --hidden
    let secret_inner = dir.join("inner_secret.txt");
    let secret_inner_out = dir.join("inner_out.txt");
    fs::write(&secret_inner, b"plausible-deniability-payload").unwrap();

    assert!(Command::new(falcon_bin())
        .env("HIDDEN_PW", "classified-inner-99")
        .args([
            "put",
            vault.to_str().unwrap(),
            secret_inner.to_str().unwrap(),
            "ops/secret.txt",
            "--hidden",
            "--passphrase-env",
            "HIDDEN_PW",
        ])
        .status()
        .unwrap()
        .success());

    assert!(Command::new(falcon_bin())
        .env("HIDDEN_PW", "classified-inner-99")
        .args([
            "get",
            vault.to_str().unwrap(),
            "ops/secret.txt",
            secret_inner_out.to_str().unwrap(),
            "--hidden",
            "--passphrase-env",
            "HIDDEN_PW",
        ])
        .status()
        .unwrap()
        .success());
    assert_eq!(
        fs::read(&secret_inner_out).unwrap(),
        b"plausible-deniability-payload"
    );

    // 6. Air-Gapped Printable SVG QR Keycards via Shamir split --qr-dir
    assert!(Command::new(falcon_bin())
        .args([
            "shamir",
            "split",
            "--threshold",
            "3",
            "--shares",
            "5",
            "--qr-dir",
            qr_dir.to_str().unwrap(),
        ])
        .status()
        .unwrap()
        .success());
    let svg1 = fs::read_to_string(qr_dir.join("falcon-share-01.svg")).unwrap();
    assert!(svg1.contains("FALCON // AIR-GAPPED KEYCARD"));

    // 7. Dead-Man's Switch: 3 wrong passphrases -> AUTO-SHRED!
    for _ in 0..3 {
        let fail = Command::new(falcon_bin())
            .env("BAD_PW", "wrong-guess")
            .args(["ls", vault.to_str().unwrap(), "--passphrase-env", "BAD_PW"])
            .status()
            .unwrap();
        assert!(!fail.success());
    }
    let after_auto_shred = Command::new(falcon_bin())
        .env("OUTER_PW", "decoy-pass-01")
        .args([
            "ls",
            vault.to_str().unwrap(),
            "--passphrase-env",
            "OUTER_PW",
        ])
        .status()
        .unwrap();
    assert!(
        !after_auto_shred.success(),
        "volume must be auto-shredded after 3 strikes"
    );

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn v4_sealed_drops_identity_seal_unseal_sanitize_and_tamper_rejection() {
    let dir = temp_dir("sealed_drops_v4");
    let alpha_id = dir.join("alpha.flcid");
    let alpha_pub = dir.join("alpha.flcpub");
    let bravo_id = dir.join("bravo.flcid");
    let bravo_pub = dir.join("bravo.flcpub");
    let jpg_in = dir.join("recon.jpg");
    let drop_pkg = dir.join("sitrep.flcpack");
    let out_file = dir.join("recovered.jpg");

    // 1. Generate two operator identities (Alpha + Bravo)
    assert!(Command::new(falcon_bin())
        .args([
            "identity",
            "generate",
            alpha_id.to_str().unwrap(),
            "--pub-out",
            alpha_pub.to_str().unwrap(),
            "--callsign",
            "ALPHA-1",
        ])
        .status()
        .unwrap()
        .success());

    assert!(Command::new(falcon_bin())
        .args([
            "identity",
            "generate",
            bravo_id.to_str().unwrap(),
            "--pub-out",
            bravo_pub.to_str().unwrap(),
            "--callsign",
            "BRAVO-2",
        ])
        .status()
        .unwrap()
        .success());

    // Inspect public bundle
    let info = Command::new(falcon_bin())
        .args(["identity", "info", bravo_pub.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(info.status.success());
    assert!(String::from_utf8_lossy(&info.stdout).contains("BRAVO-2"));

    // 2. Build a synthetic JPEG with GPS EXIF & seal it from Alpha -> Bravo with --sanitize
    let mut jpg = Vec::new();
    jpg.extend_from_slice(&[0xFF, 0xD8]);
    let exif = b"Exif\0\0GPS:37.9838N,23.7275E";
    jpg.extend_from_slice(&[0xFF, 0xE1]);
    jpg.extend_from_slice(&((exif.len() + 2) as u16).to_be_bytes());
    jpg.extend_from_slice(exif);
    jpg.extend_from_slice(&[0xFF, 0xDA, 0x00, 0x02, 0xCA, 0xFE, 0xFF, 0xD9]);
    fs::write(&jpg_in, &jpg).unwrap();

    assert!(Command::new(falcon_bin())
        .args([
            "seal",
            jpg_in.to_str().unwrap(),
            "--to",
            bravo_pub.to_str().unwrap(),
            "--from",
            alpha_id.to_str().unwrap(),
            "--out",
            drop_pkg.to_str().unwrap(),
            "--sanitize",
        ])
        .status()
        .unwrap()
        .success());

    // 3. Bravo unseals with pinned sender Alpha -> succeeds and GPS EXIF is stripped!
    let unseal = Command::new(falcon_bin())
        .args([
            "unseal",
            drop_pkg.to_str().unwrap(),
            "--identity",
            bravo_id.to_str().unwrap(),
            "--expect-sender",
            alpha_pub.to_str().unwrap(),
            "--out",
            out_file.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(unseal.status.success());
    let unseal_out = String::from_utf8_lossy(&unseal.stdout);
    assert!(unseal_out.contains("VERIFIED"));
    assert!(unseal_out.contains("MATCHED (ALPHA-1)"));

    let recovered = fs::read(&out_file).unwrap();
    assert!(!recovered.windows(3).any(|w| w == b"GPS"));
    assert_eq!(&recovered[..2], &[0xFF, 0xD8]);

    // 4. Wrong pinned sender fails
    let wrong_sender = Command::new(falcon_bin())
        .args([
            "unseal",
            drop_pkg.to_str().unwrap(),
            "--identity",
            bravo_id.to_str().unwrap(),
            "--expect-sender",
            bravo_pub.to_str().unwrap(),
            "--out",
            dir.join("fail1.jpg").to_str().unwrap(),
        ])
        .status()
        .unwrap();
    assert!(!wrong_sender.success());

    // 5. Flip 1 byte in drop package -> Ed25519 verify-before-decrypt rejects immediately
    let mut tampered = fs::read(&drop_pkg).unwrap();
    tampered[200] ^= 0x01;
    fs::write(&drop_pkg, &tampered).unwrap();
    let tampered_run = Command::new(falcon_bin())
        .args([
            "unseal",
            drop_pkg.to_str().unwrap(),
            "--identity",
            bravo_id.to_str().unwrap(),
            "--out",
            dir.join("fail2.jpg").to_str().unwrap(),
        ])
        .status()
        .unwrap();
    assert!(!tampered_run.success());

    let _ = fs::remove_dir_all(&dir);
}
