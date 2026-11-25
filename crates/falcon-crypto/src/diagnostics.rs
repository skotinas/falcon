use crate::error::Result;
use crate::integrity::compute_sector_tag;
use crate::xts::{XtsCipher, SECTOR_SIZE};
use std::time::Instant;

#[derive(Debug, Clone)]
pub struct BenchmarkReport {
    pub sample_mib: f64,
    pub aes_xts_mib_s: f64,
    pub cascade_xts_mib_s: f64,
    pub blake3_mac_mib_s: f64,
}

#[derive(Debug, Clone)]
pub struct EntropyReport {
    pub sampled_bytes: usize,
    pub shannon_bits_per_byte: f64,
    pub byte_mean: f64,
    pub min_bucket_ratio: f64,
    pub max_bucket_ratio: f64,
    pub has_visible_magic: bool,
}

pub fn run_crypto_benchmark(sectors: usize) -> Result<BenchmarkReport> {
    let count = sectors.max(256);
    let total_bytes = (count * SECTOR_SIZE) as f64;
    let sample_mib = total_bytes / (1024.0 * 1024.0);

    let aes = XtsCipher::new(&[0x11u8; 32], &[0x22u8; 32])?;
    let cascade =
        XtsCipher::new_cascade(&[0x11u8; 32], &[0x22u8; 32], &[0x33u8; 32], &[0x44u8; 32])?;

    let mut buf = [0xA5u8; SECTOR_SIZE];

    let t0 = Instant::now();
    for i in 0..count {
        aes.encrypt_sector(i as u64, &mut buf)?;
    }
    let dt_aes = t0.elapsed().as_secs_f64().max(1e-6);

    let t1 = Instant::now();
    for i in 0..count {
        cascade.encrypt_sector(i as u64, &mut buf)?;
    }
    let dt_cas = t1.elapsed().as_secs_f64().max(1e-6);

    let key = [0x77u8; 32];
    let uuid = [0x88u8; 16];
    let t2 = Instant::now();
    for i in 0..count {
        let _ = std::hint::black_box(compute_sector_tag(&key, &uuid, i as u64, &buf));
    }
    let dt_mac = t2.elapsed().as_secs_f64().max(1e-6);

    Ok(BenchmarkReport {
        sample_mib,
        aes_xts_mib_s: sample_mib / dt_aes,
        cascade_xts_mib_s: sample_mib / dt_cas,
        blake3_mac_mib_s: sample_mib / dt_mac,
    })
}

pub fn analyze_entropy(bytes: &[u8]) -> EntropyReport {
    let n = bytes.len();
    let has_visible_magic = bytes.len() >= 8 && &bytes[0..8] == b"FLCNDSK1";
    if n == 0 {
        return EntropyReport {
            sampled_bytes: 0,
            shannon_bits_per_byte: 0.0,
            byte_mean: 0.0,
            min_bucket_ratio: 0.0,
            max_bucket_ratio: 0.0,
            has_visible_magic,
        };
    }

    let mut counts = [0u64; 256];
    let mut sum = 0u64;
    for &b in bytes {
        counts[b as usize] += 1;
        sum += b as u64;
    }

    let nf = n as f64;
    let mut h = 0.0f64;
    let mut min_c = u64::MAX;
    let mut max_c = 0u64;

    for &c in &counts {
        if c < min_c {
            min_c = c;
        }
        if c > max_c {
            max_c = c;
        }
        if c > 0 {
            let p = (c as f64) / nf;
            h -= p * p.log2();
        }
    }

    let expected = nf / 256.0;
    EntropyReport {
        sampled_bytes: n,
        shannon_bits_per_byte: h,
        byte_mean: (sum as f64) / nf,
        min_bucket_ratio: (min_c as f64) / expected,
        max_bucket_ratio: (max_c as f64) / expected,
        has_visible_magic,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;
    use rand::RngCore;

    #[test]
    fn entropy_distinguishes_zero_vs_random() {
        let zeros = vec![0u8; 65_536];
        let r0 = analyze_entropy(&zeros);
        assert!(r0.shannon_bits_per_byte < 0.01);

        let mut noise = vec![0u8; 65_536];
        OsRng.fill_bytes(&mut noise);
        let r1 = analyze_entropy(&noise);
        assert!(r1.shannon_bits_per_byte > 7.95);
    }

    #[test]
    fn benchmark_returns_positive_rates() {
        let rep = run_crypto_benchmark(256).unwrap();
        assert!(rep.aes_xts_mib_s > 0.0);
        assert!(rep.cascade_xts_mib_s > 0.0);
        assert!(rep.blake3_mac_mib_s > 0.0);
    }
}
