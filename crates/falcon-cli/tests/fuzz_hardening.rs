use falcon_crypto::{
    combine_shares, parse_custody_jsonl, sanitize_file_bytes, seal_package, unseal_package,
    verify_custody_chain, CipherMode, CustodyEntry, KdfProfile, OperatorIdentity,
    OperatorPublicBundle, PqKeypair, Share, SECTOR_SIZE,
};
use falcon_fs::FalconFs;
use falcon_volume::{
    AuthMaterial, CreateOptions, MemoryBlockDevice, Volume, VolumeHeader, HEADER_MAGIC, HEADER_SIZE,
};

struct XorShift64(u64);

impl XorShift64 {
    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn fill(&mut self, buf: &mut [u8]) {
        for chunk in buf.chunks_mut(8) {
            let v = self.next_u64().to_le_bytes();
            let n = chunk.len();
            chunk.copy_from_slice(&v[..n]);
        }
    }

    fn gen_range(&mut self, max: usize) -> usize {
        if max == 0 {
            0
        } else {
            (self.next_u64() as usize) % max
        }
    }
}

#[test]
fn fuzz_volume_header_deserializer_no_panics_or_overflows() {
    let mut rng = XorShift64(0xFA1C_0401_DEAD_BEEF);
    let mut raw = [0u8; HEADER_SIZE];

    // 1. Pure random + targeted magic-prefixed mutations (1,500 iterations)
    for i in 0..1500 {
        rng.fill(&mut raw);
        if i % 2 == 0 {
            raw[0..8].copy_from_slice(&HEADER_MAGIC);
            let ver = ((i % 5) as u32).to_le_bytes();
            raw[8..12].copy_from_slice(&ver);
            raw[32..36].copy_from_slice(&(SECTOR_SIZE as u32).to_le_bytes());
        }
        let _ = VolumeHeader::deserialize(&raw);
    }

    // 2. Explicit integer-overflow adversarial header payloads
    let overflow_cases: &[(u64, u64, u64, u64)] = &[
        (u64::MAX, 16384, 32768, 65536),
        (u64::MAX / 4096 + 1, 16384, 32768, 65536),
        (1024, u64::MAX - 16, u64::MAX, 0),
        (1024, 16384, u64::MAX - 100, u64::MAX),
        (1024, 16384, 16384, u64::MAX - 8),
        (0, 16384, 32768, 65536),
        (63, 16384, 32768, 65536),
    ];
    for &(secs, int_off, data_off, bkp_off) in overflow_cases {
        raw.fill(0);
        raw[0..8].copy_from_slice(&HEADER_MAGIC);
        raw[8..12].copy_from_slice(&3u32.to_le_bytes());
        raw[12..16].copy_from_slice(&3u32.to_le_bytes()); // integrity + backup
        raw[32..36].copy_from_slice(&(SECTOR_SIZE as u32).to_le_bytes());
        raw[40..48].copy_from_slice(&secs.to_le_bytes());
        raw[48..56].copy_from_slice(&int_off.to_le_bytes());
        raw[56..64].copy_from_slice(&data_off.to_le_bytes());
        raw[64..72].copy_from_slice(&bkp_off.to_le_bytes());
        assert!(
            VolumeHeader::deserialize(&raw).is_err(),
            "overflow header must be rejected: secs={secs} int={int_off} data={data_off} bkp={bkp_off}"
        );
    }
}

#[test]
fn fuzz_falcon_fs_rejects_malicious_superblocks_inodes_and_extents() {
    let make_vol = || {
        let dev = MemoryBlockDevice::new(0);
        let opts = CreateOptions {
            data_bytes: 512 * 1024,
            kdf_params: KdfProfile::FastTest.params(),
            integrity_enabled: true,
            cipher_mode: CipherMode::Aes256Xts,
            detached_header_path: None,
            expires_at_unix: 0,
            max_failed_attempts: 0,
            label: "fuzz-fs".into(),
        };
        Volume::create(dev, &opts, &AuthMaterial::password_only(b"p"), |_, _| {}).unwrap()
    };

    // Case A: Adversarial superblocks with u64::MAX / OOM bitmap_sectors / overflow inode_sectors
    let mut vol = make_vol();
    let total = vol.sector_count();
    let bad_sbs: &[(u64, u64, u64, u64, u64, u64)] = &[
        (total, 1, u64::MAX, 2, 4, 6),
        (total, 1, 0, 1, 4, 5),
        (total, 1, 1, u64::MAX, 4, 3),
        (total, 1, 1, 2, 0, 2),
        (total, 1, 1, 2, 9999, 10001),
        (total, 1, 1, 2, 4, total),
        (total + 1, 1, 1, 2, 4, 6),
    ];
    for &(ts, bs, bsec, is, isec, ds) in bad_sbs {
        let mut sb = [0u8; SECTOR_SIZE];
        sb[0..8].copy_from_slice(b"FLCNFS01");
        sb[8..12].copy_from_slice(&1u32.to_le_bytes());
        sb[12..20].copy_from_slice(&ts.to_le_bytes());
        sb[20..28].copy_from_slice(&bs.to_le_bytes());
        sb[28..36].copy_from_slice(&bsec.to_le_bytes());
        sb[36..44].copy_from_slice(&is.to_le_bytes());
        sb[44..52].copy_from_slice(&isec.to_le_bytes());
        sb[52..60].copy_from_slice(&(isec.saturating_mul(16)).to_le_bytes());
        sb[60..68].copy_from_slice(&ds.to_le_bytes());
        vol.write_sector(0, &sb).unwrap();
        let res = FalconFs::mount(vol);
        assert!(res.is_err(), "malicious superblock should fail mount");
        vol = make_vol();
    }

    // Case B: Out-of-bounds extent pointer trying to read/wipe superblock sector 0 or bitmap sector 1
    let mut fs = FalconFs::format(vol).unwrap();
    fs.put_file("target.bin", &b"hello"[..]).unwrap();
    let mut vol = fs.into_volume();

    // Corrupt first inode (sector 2, offset 0) to point extent_head_sector to sector 1 (bitmap!)
    let mut inode_sec = [0u8; SECTOR_SIZE];
    vol.read_sector(2, &mut inode_sec).unwrap();
    inode_sec[28..36].copy_from_slice(&1u64.to_le_bytes());
    vol.write_sector(2, &inode_sec).unwrap();

    let mut fs = FalconFs::mount(vol).unwrap();
    assert!(fs.get_file("target.bin", &mut Vec::new()).is_err());
    assert!(fs.remove_file("target.bin").is_err());

    // Case C: Non-UTF8 inode path & invalid state flag (2) must return Err, never panic
    let mut vol = fs.into_volume();
    inode_sec[0] = 2; // invalid state flag
    vol.write_sector(2, &inode_sec).unwrap();
    let mut fs = FalconFs::mount(vol).unwrap();
    assert!(fs.list_files().is_err());
}

#[test]
fn fuzz_sealed_drop_identity_and_bundle_parsers() {
    let mut rng = XorShift64(0x5EA1_D809_C0DE_1234);
    let alice = OperatorIdentity::generate("ALICE");
    let bob = OperatorIdentity::generate("BOB");
    let bob_pub = bob.public_bundle();
    let alice_pub = alice.public_bundle();

    // 1. Random & truncated bytes against all 3 parsers (1,200 iterations)
    for _ in 0..1200 {
        let len = rng.gen_range(6000);
        let mut buf = vec![0u8; len];
        rng.fill(&mut buf);
        assert!(OperatorIdentity::from_bytes(&buf).is_err());
        assert!(OperatorPublicBundle::from_bytes(&buf).is_err());
        assert!(unseal_package(&bob, Some(&alice_pub), &buf).is_err());
    }

    // 2. Mutate a valid sealed drop at every critical boundary & verify 100% rejection
    let (valid_pkg, _, _) =
        seal_package(&alice, &bob_pub, "intel.dat", b"sensitive payload 12345", true).unwrap();
    assert!(unseal_package(&bob, Some(&alice_pub), &valid_pkg).is_ok());

    for pos in [0, 7, 8, 12, 24, 56, 88, 120, 132, 900, 1700, 1708, valid_pkg.len() - 65, valid_pkg.len() - 1] {
        let mut mutated = valid_pkg.clone();
        mutated[pos] ^= 0x40;
        assert!(
            unseal_package(&bob, Some(&alice_pub), &mutated).is_err(),
            "bit flip at offset {pos} must fail verification"
        );
    }

    // Truncations at multiple lengths
    for cut in [0, 8, 100, 1708, valid_pkg.len() - 64, valid_pkg.len() - 1] {
        assert!(unseal_package(&bob, Some(&alice_pub), &valid_pkg[..cut]).is_err());
    }

    // Trailing garbage appended
    let mut extended = valid_pkg.clone();
    extended.push(0x00);
    assert!(unseal_package(&bob, Some(&alice_pub), &extended).is_err());
}

#[test]
fn fuzz_shamir_parser_and_combiner_edge_cases() {
    let mut rng = XorShift64(0x5AA1_0001_2222_3333);

    // Random garbage strings
    for _ in 0..1500 {
        let len = rng.gen_range(160);
        let mut raw = vec![0u8; len];
        rng.fill(&mut raw);
        let s = String::from_utf8_lossy(&raw);
        let _ = Share::parse(&s);
    }

    // Structured malformed prefix strings
    for bad in [
        "",
        "FLCN-S1",
        "FLCN-S1-00-02-aabb-00000000",
        "FLCN-S1-01-01-aabb-00000000",
        "FLCN-S1-01-02--00000000",
        "FLCN-S1-256-02-aabb-00000000",
        "FLCN-S1-01-02-zzzz-00000000",
    ] {
        assert!(Share::parse(bad).is_err());
    }

    // Pathological manually-built Share structs passed to combine_shares
    let bad_sets = vec![
        vec![],
        vec![Share { index: 1, threshold: 0, data: vec![1, 2] }, Share { index: 2, threshold: 0, data: vec![3, 4] }],
        vec![Share { index: 1, threshold: 1, data: vec![1, 2] }, Share { index: 2, threshold: 1, data: vec![3, 4] }],
        vec![Share { index: 1, threshold: 2, data: vec![] }, Share { index: 2, threshold: 2, data: vec![] }],
        vec![Share { index: 0, threshold: 2, data: vec![1] }, Share { index: 2, threshold: 2, data: vec![2] }],
        vec![Share { index: 1, threshold: 2, data: vec![1] }, Share { index: 1, threshold: 2, data: vec![2] }],
        vec![Share { index: 1, threshold: 2, data: vec![1, 2] }, Share { index: 2, threshold: 2, data: vec![3] }],
    ];
    for set in bad_sets {
        assert!(combine_shares(&set).is_err());
    }
}

#[test]
fn fuzz_opsec_jpeg_and_png_sanitizers_never_panic() {
    let mut rng = XorShift64(0x9A17_12E0_ABCD_EF01);

    for i in 0..2000 {
        let len = rng.gen_range(2048);
        let mut buf = vec![0u8; len];
        rng.fill(&mut buf);
        if i % 3 == 0 && len >= 4 {
            // Force JPEG SOI prefix
            buf[0] = 0xFF;
            buf[1] = 0xD8;
        } else if i % 3 == 1 && len >= 16 {
            // Force PNG signature + sometimes extreme u32::MAX chunk length
            buf[0..8].copy_from_slice(b"\x89PNG\r\n\x1a\n");
            if i % 6 == 1 {
                buf[8..12].copy_from_slice(&u32::MAX.to_be_bytes());
            }
        }
        let (out, rep) = sanitize_file_bytes(&buf);
        assert!(out.len() <= buf.len() || rep.bytes_removed == 0);
    }

    // Truncated PNG without IEND must fall back untouched (not silently truncate)
    let mut trunc_png = Vec::new();
    trunc_png.extend_from_slice(b"\x89PNG\r\n\x1a\n");
    trunc_png.extend_from_slice(&0u32.to_be_bytes());
    trunc_png.extend_from_slice(b"IHDR");
    trunc_png.extend_from_slice(&[0, 0, 0, 0]);
    trunc_png.extend_from_slice(b"TRAILING");
    let (out, rep) = sanitize_file_bytes(&trunc_png);
    assert_eq!(rep.format, "png-unmodified");
    assert_eq!(out, trunc_png);
}

#[test]
fn fuzz_custody_jsonl_and_pq_keyfile_parsers() {
    let mut rng = XorShift64(0xC057_0D70_9876_5432);

    for _ in 0..1000 {
        let len = rng.gen_range(5000);
        let mut buf = vec![0u8; len];
        rng.fill(&mut buf);
        assert!(PqKeypair::from_bytes(&buf).is_err());

        let text = String::from_utf8_lossy(&buf);
        let _ = parse_custody_jsonl(&text);
    }

    // Forged custody entry with non-hex / short signature must return valid=false without panicking
    let sk = ed25519_dalek::SigningKey::from_bytes(&[0x11u8; 32]);
    let vk = sk.verifying_key();
    let bogus = CustodyEntry {
        seq: 1,
        timestamp_utc: 123,
        event: "CREATE".into(),
        slot: 0,
        detail: "bad".into(),
        prev_hash: "00".repeat(32),
        entry_hash: "ff".repeat(32),
        signature: "not-valid-hex".into(),
    };
    let rep = verify_custody_chain(&[bogus], &vk);
    assert!(!rep.valid);
}
