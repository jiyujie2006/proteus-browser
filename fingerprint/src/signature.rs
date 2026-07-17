use std::collections::BTreeMap;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::de::{Error as DeError, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::{Map, Number, Value};
use sha2::{Digest, Sha256};

use crate::dataset::Dataset;
use crate::error::{FingerprintError, Result};
use crate::generator::verify_reproducible;
use crate::model::{
    Canonicalization, ConfigBody, SignatureAlgorithm, SignatureEnvelope, SignedProfileConfig,
};
use crate::validate::validate;

pub const CONFIG_SIGNATURE_DOMAIN: &str = "proteus-profile-config/v1";
const SIGNING_PREFIX: &[u8] = b"PROTEUS-PROFILE-CONFIG\0v1\0";
const MAX_CONFIG_BYTES: usize = 1_048_576;

/// A local trust store provisioned by the Manager/installation boundary. The
/// shared browser binary must not bake one user's Manager key into itself.
#[derive(Debug, Default, Clone)]
pub struct TrustStore {
    keys: BTreeMap<String, VerifyingKey>,
}

impl TrustStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, key_id: impl Into<String>, key: VerifyingKey) -> Result<()> {
        let key_id = key_id.into();
        validate_key_id(&key_id)?;
        if self.keys.contains_key(&key_id) {
            return Err(FingerprintError::InvalidSignatureEnvelope(format!(
                "duplicate trust-store keyId {key_id}"
            )));
        }
        self.keys.insert(key_id, key);
        Ok(())
    }

    pub fn insert_base64(&mut self, key_id: impl Into<String>, encoded: &str) -> Result<()> {
        let bytes = STANDARD.decode(encoded)?;
        let bytes: [u8; 32] = bytes.try_into().map_err(|bytes: Vec<u8>| {
            FingerprintError::InvalidSignatureEnvelope(format!(
                "Ed25519 public key must be 32 bytes, got {}",
                bytes.len()
            ))
        })?;
        let key = VerifyingKey::from_bytes(&bytes).map_err(|error| {
            FingerprintError::InvalidSignatureEnvelope(format!(
                "invalid Ed25519 public key: {error}"
            ))
        })?;
        self.insert(key_id, key)
    }

    pub fn get(&self, key_id: &str) -> Option<&VerifyingKey> {
        self.keys.get(key_id)
    }
}

/// Stable key identifier derived from the first 128 bits of SHA-256(public key).
pub fn derive_key_id(key: &VerifyingKey) -> String {
    let digest = Sha256::digest(key.as_bytes());
    let mut out = String::from("ed25519:");
    for byte in &digest[..16] {
        use std::fmt::Write as _;
        write!(&mut out, "{byte:02x}").expect("writing to String cannot fail");
    }
    out
}

/// RFC 8785-compatible canonical bytes for the constrained Profile Config
/// schema. Object keys are sorted by UTF-16 code units, strings use JSON
/// escaping, and all supported numbers are finite and in the non-exponential
/// range used by this schema.
pub fn canonical_payload(body: &ConfigBody) -> Result<Vec<u8>> {
    canonical_value(&serde_json::to_value(body)?)
}

pub fn signing_input(body: &ConfigBody, key_id: &str) -> Result<Vec<u8>> {
    signing_input_value(&serde_json::to_value(body)?, key_id)
}

fn signing_input_value(value: &Value, key_id: &str) -> Result<Vec<u8>> {
    validate_key_id(key_id)?;
    let payload = canonical_value(value)?;
    let mut input = Vec::with_capacity(SIGNING_PREFIX.len() + key_id.len() + 1 + payload.len());
    input.extend_from_slice(SIGNING_PREFIX);
    input.extend_from_slice(key_id.as_bytes());
    input.push(0);
    input.extend_from_slice(&payload);
    Ok(input)
}

pub fn sign_config(
    body: ConfigBody,
    signing_key: &SigningKey,
    key_id: Option<&str>,
) -> Result<SignedProfileConfig> {
    let resolved_key_id = key_id
        .map(str::to_owned)
        .unwrap_or_else(|| derive_key_id(&signing_key.verifying_key()));
    validate_key_id(&resolved_key_id)?;
    let signature: Signature = signing_key.sign(&signing_input(&body, &resolved_key_id)?);
    Ok(SignedProfileConfig {
        body,
        signature: SignatureEnvelope {
            algorithm: SignatureAlgorithm::Ed25519,
            canonicalization: Canonicalization::Rfc8785,
            domain: CONFIG_SIGNATURE_DOMAIN.into(),
            key_id: resolved_key_id,
            value: STANDARD.encode(signature.to_bytes()),
        },
    })
}

/// Parse and cryptographically verify a flat signed Profile Config document.
/// Duplicate keys, unknown keys, oversized input, unsupported schema revision,
/// unknown trust anchors, and any tampering all fail closed.
pub fn verify_signed_json(bytes: &[u8], trust_store: &TrustStore) -> Result<SignedProfileConfig> {
    if bytes.len() > MAX_CONFIG_BYTES {
        return Err(FingerprintError::ConfigTooLarge(MAX_CONFIG_BYTES));
    }
    let mut value = parse_unique_json(bytes)?;
    let object = value.as_object_mut().ok_or_else(|| {
        FingerprintError::InvalidSignatureEnvelope("top-level config must be an object".into())
    })?;
    let signature_value = object.remove("signature").ok_or_else(|| {
        FingerprintError::InvalidSignatureEnvelope("missing signature object".into())
    })?;
    let envelope: SignatureEnvelope = serde_json::from_value(signature_value).map_err(|error| {
        FingerprintError::InvalidSignatureEnvelope(format!("invalid signature object: {error}"))
    })?;
    validate_envelope(&envelope)?;
    let raw_body = Value::Object(object.clone());

    let key = trust_store
        .get(&envelope.key_id)
        .ok_or_else(|| FingerprintError::UnknownKey(envelope.key_id.clone()))?;
    let signature_bytes = STANDARD.decode(&envelope.value)?;
    let parsed_signature = Signature::from_slice(&signature_bytes).map_err(|error| {
        FingerprintError::InvalidSignatureEnvelope(format!(
            "signature value must encode 64 Ed25519 bytes: {error}"
        ))
    })?;
    key.verify_strict(
        &signing_input_value(&raw_body, &envelope.key_id)?,
        &parsed_signature,
    )
    .map_err(|_| FingerprintError::SignatureVerification)?;

    let body: ConfigBody = serde_json::from_value(raw_body.clone())?;
    if body.schema_version != crate::generator::PROFILE_SCHEMA_VERSION {
        return Err(FingerprintError::UnsupportedSchema(body.schema_version));
    }
    // Serde's Option fields normally accept omission as None. The Profile
    // Config schema requires explicit nulls for those fields, and signatures
    // are over the raw document. Re-projecting the typed body and comparing its
    // canonical value rejects signed-but-incomplete documents instead of
    // silently normalizing them into a different signed value.
    if canonical_value(&raw_body)? != canonical_payload(&body)? {
        return Err(FingerprintError::InvalidSignatureEnvelope(
            "config body is not the complete strict schema projection".into(),
        ));
    }

    Ok(SignedProfileConfig {
        body,
        signature: SignatureEnvelope {
            value: STANDARD.encode(parsed_signature.to_bytes()),
            ..envelope
        },
    })
}

/// Full engine-ingest boundary: signature and semantic validation must both
/// succeed before the caller receives a config.
pub fn verify_and_validate_signed_json(
    bytes: &[u8],
    trust_store: &TrustStore,
    dataset: &Dataset,
) -> Result<SignedProfileConfig> {
    let signed = verify_signed_json(bytes, trust_store)?;
    let report = validate(&signed.body, dataset);
    if !report.valid {
        let summary = report
            .issues
            .iter()
            .map(|issue| format!("{}: {}", issue.rule_id, issue.reason))
            .collect::<Vec<_>>()
            .join("; ");
        return Err(FingerprintError::Validation(summary));
    }
    verify_reproducible(&signed.body, dataset)?;
    Ok(signed)
}

impl SignedProfileConfig {
    pub fn to_value(&self) -> Result<Value> {
        let mut object = serde_json::to_value(&self.body)?
            .as_object()
            .cloned()
            .ok_or_else(|| {
                FingerprintError::CanonicalJson("config body is not an object".into())
            })?;
        object.insert("signature".into(), serde_json::to_value(&self.signature)?);
        Ok(Value::Object(object))
    }

    pub fn to_json_pretty(&self) -> Result<Vec<u8>> {
        Ok(serde_json::to_vec_pretty(&self.to_value()?)?)
    }

    pub fn to_canonical_json(&self) -> Result<Vec<u8>> {
        canonical_value(&self.to_value()?)
    }
}

fn validate_envelope(envelope: &SignatureEnvelope) -> Result<()> {
    if envelope.algorithm != SignatureAlgorithm::Ed25519 {
        return Err(FingerprintError::InvalidSignatureEnvelope(
            "algorithm must be Ed25519".into(),
        ));
    }
    if envelope.canonicalization != Canonicalization::Rfc8785 {
        return Err(FingerprintError::InvalidSignatureEnvelope(
            "canonicalization must be RFC8785".into(),
        ));
    }
    if envelope.domain != CONFIG_SIGNATURE_DOMAIN {
        return Err(FingerprintError::InvalidSignatureEnvelope(format!(
            "domain must be {CONFIG_SIGNATURE_DOMAIN}"
        )));
    }
    validate_key_id(&envelope.key_id)
}

fn validate_key_id(key_id: &str) -> Result<()> {
    if key_id.is_empty()
        || key_id.len() > 96
        || !key_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte))
    {
        return Err(FingerprintError::InvalidSignatureEnvelope(
            "keyId must be 1-96 ASCII alphanumeric/._:- characters".into(),
        ));
    }
    Ok(())
}

fn canonical_value(value: &Value) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    write_canonical(value, &mut output)?;
    Ok(output)
}

fn write_canonical(value: &Value, output: &mut Vec<u8>) -> Result<()> {
    match value {
        Value::Null => output.extend_from_slice(b"null"),
        Value::Bool(true) => output.extend_from_slice(b"true"),
        Value::Bool(false) => output.extend_from_slice(b"false"),
        Value::Number(number) => write_number(number, output)?,
        Value::String(string) => {
            output.extend_from_slice(serde_json::to_string(string)?.as_bytes());
        }
        Value::Array(values) => {
            output.push(b'[');
            for (index, item) in values.iter().enumerate() {
                if index > 0 {
                    output.push(b',');
                }
                write_canonical(item, output)?;
            }
            output.push(b']');
        }
        Value::Object(object) => {
            output.push(b'{');
            let mut keys = object.keys().collect::<Vec<_>>();
            keys.sort_by(|left, right| left.encode_utf16().cmp(right.encode_utf16()));
            for (index, key) in keys.into_iter().enumerate() {
                if index > 0 {
                    output.push(b',');
                }
                output.extend_from_slice(serde_json::to_string(key)?.as_bytes());
                output.push(b':');
                write_canonical(
                    object
                        .get(key)
                        .expect("key was obtained from this exact object"),
                    output,
                )?;
            }
            output.push(b'}');
        }
    }
    Ok(())
}

fn write_number(number: &Number, output: &mut Vec<u8>) -> Result<()> {
    let rendered = if let Some(value) = number.as_i64() {
        value.to_string()
    } else if let Some(value) = number.as_u64() {
        value.to_string()
    } else {
        let value = number
            .as_f64()
            .ok_or_else(|| FingerprintError::CanonicalJson("unrepresentable number".into()))?;
        if !value.is_finite() {
            return Err(FingerprintError::CanonicalJson(
                "non-finite numbers are forbidden".into(),
            ));
        }
        let absolute = value.abs();
        if absolute != 0.0 && !(1e-6..1e21).contains(&absolute) {
            return Err(FingerprintError::CanonicalJson(
                "number is outside the Profile Config canonicalization range".into(),
            ));
        }
        if value == 0.0 {
            "0".into()
        } else {
            value.to_string()
        }
    };
    output.extend_from_slice(rendered.as_bytes());
    Ok(())
}

// serde_json normally accepts duplicate object keys and keeps the last value.
// The signature boundary must reject them so parsers in different languages
// cannot disagree about which value was signed.
struct UniqueJson(Value);

impl<'de> Deserialize<'de> for UniqueJson {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(UniqueJsonVisitor)
    }
}

struct UniqueJsonVisitor;

impl<'de> Visitor<'de> for UniqueJsonVisitor {
    type Value = UniqueJson;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a JSON value without duplicate object keys")
    }

    fn visit_unit<E>(self) -> std::result::Result<Self::Value, E> {
        Ok(UniqueJson(Value::Null))
    }

    fn visit_none<E>(self) -> std::result::Result<Self::Value, E> {
        Ok(UniqueJson(Value::Null))
    }

    fn visit_bool<E>(self, value: bool) -> std::result::Result<Self::Value, E> {
        Ok(UniqueJson(Value::Bool(value)))
    }

    fn visit_i64<E>(self, value: i64) -> std::result::Result<Self::Value, E> {
        Ok(UniqueJson(Value::Number(value.into())))
    }

    fn visit_u64<E>(self, value: u64) -> std::result::Result<Self::Value, E> {
        Ok(UniqueJson(Value::Number(value.into())))
    }

    fn visit_f64<E>(self, value: f64) -> std::result::Result<Self::Value, E>
    where
        E: DeError,
    {
        Number::from_f64(value)
            .map(Value::Number)
            .map(UniqueJson)
            .ok_or_else(|| E::custom("non-finite JSON number"))
    }

    fn visit_str<E>(self, value: &str) -> std::result::Result<Self::Value, E> {
        Ok(UniqueJson(Value::String(value.into())))
    }

    fn visit_string<E>(self, value: String) -> std::result::Result<Self::Value, E> {
        Ok(UniqueJson(Value::String(value)))
    }

    fn visit_seq<A>(self, mut sequence: A) -> std::result::Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element::<UniqueJson>()? {
            values.push(value.0);
        }
        Ok(UniqueJson(Value::Array(values)))
    }

    fn visit_map<A>(self, mut map: A) -> std::result::Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut object = Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if object.contains_key(&key) {
                return Err(A::Error::custom(format!("duplicate object key `{key}`")));
            }
            let value = map.next_value::<UniqueJson>()?;
            object.insert(key, value.0);
        }
        Ok(UniqueJson(Value::Object(object)))
    }
}

pub(crate) fn parse_unique_json(bytes: &[u8]) -> Result<Value> {
    match serde_json::from_slice::<UniqueJson>(bytes) {
        Ok(value) => Ok(value.0),
        Err(error) => {
            let message = error.to_string();
            if let Some(rest) = message.split("duplicate object key `").nth(1) {
                let key = rest.split('`').next().unwrap_or("unknown");
                Err(FingerprintError::DuplicateKey(key.into()))
            } else {
                Err(FingerprintError::Json(error))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_KEY_ID: &str = "proteus-m1a-test-key";

    fn raw_golden_body() -> Value {
        let mut value: Value = serde_json::from_slice(include_bytes!(
            "../conformance/v1/golden/windows-chrome-us.signed.json"
        ))
        .expect("parse golden");
        value
            .as_object_mut()
            .expect("golden object")
            .remove("signature");
        value
    }

    fn test_key() -> SigningKey {
        let bytes = STANDARD
            .decode("//79/Pv6+fj39vX08/Lx8O/u7ezr6uno5+bl5OPi4eA=")
            .expect("test key");
        SigningKey::from_bytes(&bytes.try_into().expect("32-byte key"))
    }

    fn sign_raw_body(mut body: Value, key: &SigningKey) -> Vec<u8> {
        let signature: Signature =
            key.sign(&signing_input_value(&body, TEST_KEY_ID).expect("raw signing input"));
        body.as_object_mut().expect("body object").insert(
            "signature".into(),
            serde_json::to_value(SignatureEnvelope {
                algorithm: SignatureAlgorithm::Ed25519,
                canonicalization: Canonicalization::Rfc8785,
                domain: CONFIG_SIGNATURE_DOMAIN.into(),
                key_id: TEST_KEY_ID.into(),
                value: STANDARD.encode(signature.to_bytes()),
            })
            .expect("signature envelope"),
        );
        serde_json::to_vec(&body).expect("signed raw body")
    }

    fn trust(key: &SigningKey) -> TrustStore {
        let mut trust = TrustStore::new();
        trust
            .insert(TEST_KEY_ID, key.verifying_key())
            .expect("trust test key");
        trust
    }

    #[test]
    fn correctly_signed_unknown_fields_still_fail_closed() {
        let key = test_key();
        let mut body = raw_golden_body();
        body.as_object_mut()
            .expect("body object")
            .insert("unexpected".into(), true.into());
        assert!(matches!(
            verify_signed_json(&sign_raw_body(body, &key), &trust(&key)),
            Err(FingerprintError::Json(_))
        ));
    }

    #[test]
    fn correctly_signed_omitted_nulls_are_not_silently_defaulted() {
        let key = test_key();
        let mut body = raw_golden_body();
        body["persona"]["device"]
            .as_object_mut()
            .expect("device")
            .remove("model");
        body["navigator"]
            .as_object_mut()
            .expect("navigator")
            .remove("oscpu");
        assert!(matches!(
            verify_signed_json(&sign_raw_body(body, &key), &trust(&key)),
            Err(FingerprintError::InvalidSignatureEnvelope(message))
                if message.contains("complete strict schema projection")
        ));
    }
}
