use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::error::{FingerprintError, Result};

type HmacSha256 = Hmac<Sha256>;

/// Domain-separated deterministic sampler rooted in a 32-byte profile seed.
#[derive(Debug, Clone)]
pub struct DeterministicSampler {
    seed: [u8; 32],
}

impl DeterministicSampler {
    pub const DOMAIN: &'static [u8] = b"proteus-fingerprint-sampler/v1\0";

    pub const fn new(seed: [u8; 32]) -> Self {
        Self { seed }
    }

    /// Derive 32 deterministic bytes for an independent factor label.
    pub fn derive(&self, label: &str, counter: u32) -> [u8; 32] {
        let mut mac = HmacSha256::new_from_slice(&self.seed)
            .expect("HMAC accepts a key of any size; the seed is fixed at 32 bytes");
        mac.update(Self::DOMAIN);
        mac.update(label.as_bytes());
        mac.update(&[0]);
        mac.update(&counter.to_be_bytes());
        mac.finalize().into_bytes().into()
    }

    /// Choose an index from positive integer weights without modulo bias.
    pub fn choose_weighted(&self, label: &str, weights: &[u32]) -> Result<usize> {
        if weights.is_empty() {
            return Err(FingerprintError::NoCandidate(format!(
                "{label}: candidate list is empty"
            )));
        }
        if weights.contains(&0) {
            return Err(FingerprintError::InvalidDataset(format!(
                "{label}: all candidate weights must be positive"
            )));
        }
        let total = weights
            .iter()
            .try_fold(0_u64, |sum, weight| sum.checked_add(u64::from(*weight)))
            .ok_or_else(|| {
                FingerprintError::InvalidDataset(format!("{label}: weight sum overflow"))
            })?;

        // Rejection sampling avoids the small modulo bias that would otherwise
        // make the declared weights inexact.
        let zone = u64::MAX - (u64::MAX % total);
        let mut counter = 0_u32;
        let draw = loop {
            let bytes = self.derive(label, counter);
            let value = u64::from_be_bytes(bytes[..8].try_into().expect("8-byte slice"));
            if value < zone {
                break value % total;
            }
            counter = counter.checked_add(1).ok_or_else(|| {
                FingerprintError::NoCandidate(format!("{label}: sampler counter exhausted"))
            })?;
        };

        let mut cursor = 0_u64;
        for (index, weight) in weights.iter().enumerate() {
            cursor += u64::from(*weight);
            if draw < cursor {
                return Ok(index);
            }
        }
        Err(FingerprintError::NoCandidate(format!(
            "{label}: weighted choice did not resolve"
        )))
    }

    /// Stable URL-safe token for browser-facing identifiers such as media
    /// device IDs. The bytes remain independently domain-separated by `label`.
    pub fn stable_token(&self, label: &str, byte_len: usize) -> String {
        let bytes = self.derive(label, 0);
        URL_SAFE_NO_PAD.encode(&bytes[..byte_len.min(bytes.len())])
    }
}
