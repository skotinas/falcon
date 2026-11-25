use crate::error::{CryptoError, Result};
use rand::rngs::OsRng;
use rand::RngCore;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

const SHARE_PREFIX: &str = "FLCN-S1";
const CHECKSUM_DOMAIN: &[u8] = b"falcon-v2-shamir-share-mac";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Share {
    pub index: u8,     // 1..=total (x-coordinate in GF(256), never 0)
    pub threshold: u8, // M
    pub data: Vec<u8>,
}

impl Drop for Share {
    fn drop(&mut self) {
        self.data.zeroize();
    }
}

impl Share {
    pub fn encode(&self) -> String {
        let tag = share_checksum(self.index, self.threshold, &self.data);
        format!(
            "{SHARE_PREFIX}-{:02}-{:02}-{}-{}",
            self.index,
            self.threshold,
            hex::encode(&self.data),
            hex::encode(tag)
        )
    }

    pub fn parse(input: &str) -> Result<Self> {
        let trimmed = input.trim();
        let parts: Vec<&str> = trimmed.split('-').collect();
        if parts.len() != 6 || parts[0] != "FLCN" || parts[1] != "S1" {
            return Err(CryptoError::ShamirError("malformed share format".into()));
        }
        let index: u8 = parts[2]
            .parse()
            .map_err(|_| CryptoError::ShamirError("invalid share index".into()))?;
        let threshold: u8 = parts[3]
            .parse()
            .map_err(|_| CryptoError::ShamirError("invalid share threshold".into()))?;
        if index == 0 || threshold < 2 {
            return Err(CryptoError::ShamirError("invalid index or threshold".into()));
        }
        let data = hex::decode(parts[4])
            .map_err(|_| CryptoError::ShamirError("invalid share hex payload".into()))?;
        let tag = hex::decode(parts[5])
            .map_err(|_| CryptoError::ShamirError("invalid share checksum hex".into()))?;
        if data.is_empty() || tag.len() != 4 {
            return Err(CryptoError::ShamirError("invalid share length".into()));
        }

        let expected = share_checksum(index, threshold, &data);
        if !bool::from(expected.as_slice().ct_eq(&tag)) {
            return Err(CryptoError::ShamirError(format!(
                "checksum mismatch on share #{index}"
            )));
        }

        Ok(Self {
            index,
            threshold,
            data,
        })
    }
}

fn share_checksum(index: u8, threshold: u8, data: &[u8]) -> [u8; 4] {
    let mut h = blake3::Hasher::new();
    h.update(CHECKSUM_DOMAIN);
    h.update(&[index, threshold]);
    h.update(data);
    let digest = h.finalize();
    let mut out = [0u8; 4];
    out.copy_from_slice(&digest.as_bytes()[..4]);
    out
}

// Constant-time GF(2^8) multiplication modulo AES polynomial x^8 + x^4 + x^3 + x + 1 (0x11B).
fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut p = 0u8;
    for _ in 0..8 {
        let mask = 0u8.wrapping_sub(b & 1);
        p ^= a & mask;
        let hi = 0u8.wrapping_sub(a >> 7);
        a = (a << 1) ^ (0x1B & hi);
        b >>= 1;
    }
    p
}

// Multiplicative inverse via Fermat's little theorem: a^254 = a^-1 in GF(2^8) (constant time).
fn gf_inv(a: u8) -> u8 {
    let mut base = a;
    let mut res = 1u8;
    let mut exp = 254u8;
    for _ in 0..8 {
        let take = 0u8.wrapping_sub(exp & 1);
        let prod = gf_mul(res, base);
        res = (res & !take) | (prod & take);
        base = gf_mul(base, base);
        exp >>= 1;
    }
    res
}

pub fn split_secret(secret: &[u8], threshold: u8, total: u8) -> Result<Vec<Share>> {
    if secret.is_empty() {
        return Err(CryptoError::ShamirError("secret cannot be empty".into()));
    }
    if threshold < 2 || total < threshold || total > 16 {
        return Err(CryptoError::ShamirError(
            "require 2 <= threshold <= total <= 16".into(),
        ));
    }

    let mut shares: Vec<Share> = (1..=total)
        .map(|i| Share {
            index: i,
            threshold,
            data: vec![0u8; secret.len()],
        })
        .collect();

    let mut coeffs = vec![0u8; threshold as usize];
    for (byte_i, &secret_byte) in secret.iter().enumerate() {
        coeffs[0] = secret_byte;
        OsRng.fill_bytes(&mut coeffs[1..]);

        for share in &mut shares {
            // Horner evaluation of f(x) over GF(256)
            let x = share.index;
            let mut acc = 0u8;
            for &c in coeffs.iter().rev() {
                acc = gf_mul(acc, x) ^ c;
            }
            share.data[byte_i] = acc;
        }
    }
    coeffs.zeroize();

    Ok(shares)
}

pub fn combine_shares(shares: &[Share]) -> Result<Vec<u8>> {
    if shares.len() < 2 {
        return Err(CryptoError::ShamirError("need at least 2 shares".into()));
    }
    let threshold = shares[0].threshold as usize;
    let len = shares[0].data.len();
    if threshold < 2 || len == 0 {
        return Err(CryptoError::ShamirError(
            "invalid share threshold or empty payload".into(),
        ));
    }
    if shares.len() < threshold {
        return Err(CryptoError::ShamirError(format!(
            "need at least {threshold} shares, got {}",
            shares.len()
        )));
    }

    // Validate consistent length, threshold, and distinct non-zero x-coordinates
    let used = &shares[..threshold];
    for (i, s) in used.iter().enumerate() {
        if s.index == 0 || s.data.len() != len || s.threshold as usize != threshold {
            return Err(CryptoError::ShamirError("inconsistent share metadata".into()));
        }
        for other in &used[i + 1..] {
            if s.index == other.index {
                return Err(CryptoError::ShamirError(format!(
                    "duplicate share index #{}",
                    s.index
                )));
            }
        }
    }

    // Precompute Lagrange basis coefficients L_i(0) = prod_{j!=i} x_j / (x_j ^ x_i)
    let mut lagrange = vec![0u8; threshold];
    for i in 0..threshold {
        let xi = used[i].index;
        let mut num = 1u8;
        let mut den = 1u8;
        for (j, sj) in used.iter().enumerate() {
            if i == j {
                continue;
            }
            let xj = sj.index;
            num = gf_mul(num, xj);
            den = gf_mul(den, xj ^ xi);
        }
        lagrange[i] = gf_mul(num, gf_inv(den));
    }

    let mut out = vec![0u8; len];
    for (byte_i, out_byte) in out.iter_mut().enumerate() {
        let mut acc = 0u8;
        for (i, s) in used.iter().enumerate() {
            acc ^= gf_mul(s.data[byte_i], lagrange[i]);
        }
        *out_byte = acc;
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shamir_3_of_5_split_encode_parse_and_combine() {
        let secret: [u8; 32] = [
            0xde, 0xad, 0xbe, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc,
            0xba, 0x98, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xa0, 0xb0, 0xc0,
            0xd0, 0xe0, 0xf0, 0x0f,
        ];
        let shares = split_secret(&secret, 3, 5).unwrap();
        assert_eq!(shares.len(), 5);

        let encoded: Vec<String> = shares.iter().map(Share::encode).collect();
        let parsed: Vec<Share> = encoded.iter().map(|s| Share::parse(s).unwrap()).collect();

        // Any 3 shares recover exact secret
        let rec1 = combine_shares(&[parsed[0].clone(), parsed[2].clone(), parsed[4].clone()]).unwrap();
        assert_eq!(rec1.as_slice(), &secret);

        let rec2 = combine_shares(&[parsed[1].clone(), parsed[3].clone(), parsed[4].clone()]).unwrap();
        assert_eq!(rec2.as_slice(), &secret);

        // Fewer than 3 shares rejected
        assert!(combine_shares(&[parsed[0].clone(), parsed[1].clone()]).is_err());

        // Corrupted checksum rejected
        let mut bad = encoded[0].clone();
        bad.pop();
        bad.push(if encoded[0].ends_with('0') { '1' } else { '0' });
        assert!(Share::parse(&bad).is_err());
    }
}
