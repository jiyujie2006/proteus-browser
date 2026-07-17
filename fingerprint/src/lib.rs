//! Proteus M1A fingerprint generation core.
//!
//! This crate implements the part of M1 that can be completed without a
//! Chromium checkout: deterministic persona sampling, strict semantic
//! validation, stable config serialization, and fail-closed Ed25519 signing.
//! It does **not** claim that Chromium consumes the config yet.

pub mod dataset;
pub mod error;
pub mod generator;
pub mod model;
pub mod sampler;
mod schema_contract;
pub mod signature;
pub mod validate;

pub use dataset::Dataset;
pub use error::{FingerprintError, Result};
pub use generator::{GeneratedProfile, generate, rescore, verify_reproducible};
pub use model::{
    ConfigBody, GenerateRequest, SignatureEnvelope, SignedProfileConfig, ValidationIssue,
    ValidationReport,
};
pub use signature::{
    CONFIG_SIGNATURE_DOMAIN, TrustStore, canonical_payload, derive_key_id, sign_config,
    signing_input, verify_and_validate_signed_json, verify_signed_json,
};
pub use validate::validate;

/// Version of this generator implementation, recorded in config provenance.
pub const GENERATOR_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Version of the semantic rule contract implemented by this crate. The shared
/// dataset and the independent Node catalog must carry the same value.
pub const RULES_VERSION: &str = "1.0.0";
