//! Small, dependency-free predicates for the constraints that Serde's Rust
//! types cannot express on their own. Keep these aligned with
//! docs/schemas/profile-config.schema.json.
pub(crate) fn is_full_version(value: &str) -> bool {
    let segments = value.split('.').collect::<Vec<_>>();
    (2..=4).contains(&segments.len())
        && segments
            .iter()
            .all(|segment| !segment.is_empty() && segment.bytes().all(|byte| byte.is_ascii_digit()))
}

pub(crate) fn is_seed(value: &str) -> bool {
    value.len() == 44
        && value.as_bytes()[43] == b'='
        && value.as_bytes()[..43]
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(*byte, b'+' | b'/'))
}

pub(crate) fn is_lower_hex_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub(crate) fn is_media_device_kind(value: &str) -> bool {
    matches!(value, "audioinput" | "audiooutput" | "videoinput")
}

pub(crate) fn is_canonical_f64(value: f64) -> bool {
    if !value.is_finite() {
        return false;
    }
    let absolute = value.abs();
    absolute == 0.0 || (1e-6..1e21).contains(&absolute)
}
