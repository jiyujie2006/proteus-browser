use thiserror::Error;

/// Library result type.
pub type Result<T> = std::result::Result<T, FingerprintError>;

/// Fail-closed errors returned at the config generation and ingest boundary.
#[derive(Debug, Error)]
pub enum FingerprintError {
    #[error("invalid JSON: {0}")]
    Json(#[from] serde_json::Error),

    #[error("invalid base64: {0}")]
    Base64(#[from] base64::DecodeError),

    #[error("invalid dataset: {0}")]
    InvalidDataset(String),

    #[error("invalid generation request: {0}")]
    InvalidRequest(String),

    #[error("no coherent candidate exists: {0}")]
    NoCandidate(String),

    #[error("generated config failed strict validation: {0}")]
    Validation(String),

    #[error("signed config is not the deterministic output for its declared inputs: {0}")]
    DeterministicMismatch(String),

    #[error("config exceeds the {0}-byte ingest limit")]
    ConfigTooLarge(usize),

    #[error("duplicate JSON object key: {0}")]
    DuplicateKey(String),

    #[error("unsupported profile schema version: {0}")]
    UnsupportedSchema(String),

    #[error("invalid signature envelope: {0}")]
    InvalidSignatureEnvelope(String),

    #[error("unknown signing key: {0}")]
    UnknownKey(String),

    #[error("signature verification failed")]
    SignatureVerification,

    #[error("canonical JSON error: {0}")]
    CanonicalJson(String),
}
