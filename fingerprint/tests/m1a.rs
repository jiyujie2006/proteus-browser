use std::collections::BTreeSet;
use std::fs::read;
use std::path::PathBuf;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use ed25519_dalek::SigningKey;
use proteus_fingerprint::model::{CpuArch, DeviceClass, QuicPolicy};
use proteus_fingerprint::{
    Dataset, FingerprintError, GenerateRequest, RULES_VERSION, TrustStore, canonical_payload,
    generate, rescore, sign_config, signing_input, validate, verify_and_validate_signed_json,
    verify_reproducible, verify_signed_json,
};
use sha2::{Digest, Sha256};

fn repo_path(relative: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join(relative)
}

fn dataset() -> Dataset {
    Dataset::from_json(
        &read(repo_path("verify-lab/data/reference.json")).expect("read shared seed dataset"),
    )
    .expect("parse shared seed dataset")
}

fn request() -> GenerateRequest {
    serde_json::from_slice(
        &read(repo_path(
            "fingerprint/fixtures/request-windows-chrome.json",
        ))
        .expect("read request fixture"),
    )
    .expect("parse request fixture")
}

fn signing_key() -> SigningKey {
    let bytes = STANDARD
        .decode("//79/Pv6+fj39vX08/Lx8O/u7ezr6uno5+bl5OPi4eA=")
        .expect("test key base64");
    SigningKey::from_bytes(&bytes.try_into().expect("32-byte test key"))
}

#[test]
fn shared_dataset_loads_and_is_versioned() {
    let dataset = dataset();
    assert_eq!(dataset.version(), "0.2.0-m1a-seed");
    assert_eq!(
        dataset.sha256(),
        "238d78daa773035cabc29ab7b44248dd6736a58e55d02f914e991eaf40885ed5"
    );
    assert_eq!(dataset.rules_version(), "1.0.0");
    assert_eq!(dataset.rules_version(), RULES_VERSION);
    assert!(!dataset.engine_targets().is_empty());
    assert!(!dataset.gpu_profiles_by_os()["Windows"].is_empty());
}

#[test]
fn shared_dataset_rejects_ambiguous_duplicate_keys() {
    let bytes =
        read(repo_path("verify-lab/data/reference.json")).expect("read shared seed dataset");
    let mut duplicate = br#"{"_version":"ignored","#.to_vec();
    duplicate.extend_from_slice(&bytes[1..]);
    assert!(matches!(
        Dataset::from_json(&duplicate),
        Err(FingerprintError::DuplicateKey(key)) if key == "_version"
    ));
}

#[test]
fn shared_dataset_rejects_unknown_root_tables() {
    let bytes =
        read(repo_path("verify-lab/data/reference.json")).expect("read shared seed dataset");
    let mut raw: serde_json::Value =
        serde_json::from_slice(&bytes).expect("parse shared seed dataset as JSON");
    raw["screenTupleByClass"] = serde_json::json!({});
    assert!(matches!(
        Dataset::from_json(&serde_json::to_vec(&raw).expect("serialize malformed dataset")),
        Err(FingerprintError::Json(error))
            if error.to_string().contains("unknown field")
    ));
}

#[test]
fn generation_is_deterministic_and_strictly_valid() {
    let dataset = dataset();
    let request = request();
    let first = generate(&request, &dataset).expect("first generation");
    let second = generate(&request, &dataset).expect("second generation");

    assert_eq!(first, second);
    assert_eq!(
        canonical_payload(&first.body).expect("canonical payload"),
        canonical_payload(&second.body).expect("canonical payload")
    );
    let report = validate(&first.body, &dataset);
    assert!(report.valid, "{:?}", report.issues);
    assert_eq!(
        rescore(&first.body, &dataset).expect("rescore"),
        first.body.rarity
    );
}

#[test]
fn explicit_major_stays_replayable_with_multiple_dataset_targets() {
    let original = dataset();
    let dataset_bytes =
        read(repo_path("verify-lab/data/reference.json")).expect("read shared seed dataset");
    let mut raw: serde_json::Value =
        serde_json::from_slice(&dataset_bytes).expect("parse shared seed dataset as JSON");
    let mut alternate = raw["engineTargets"][0].clone();
    alternate["majorVersion"] = serde_json::json!(149);
    alternate["fullVersion"] = serde_json::json!("149.0.0.0");
    alternate["weight"] = serde_json::json!(u32::MAX);
    raw["engineTargets"]
        .as_array_mut()
        .expect("engineTargets array")
        .push(alternate);
    let modified_bytes = serde_json::to_vec(&raw).expect("serialize modified dataset");
    let dataset = Dataset::from_json(&modified_bytes).expect("parse modified dataset");
    assert_ne!(dataset.sha256(), original.sha256());

    let request = request();
    let generated = generate(&request, &dataset).expect("pinned-major generation");
    assert_eq!(generated.body.engine.major_version, 150);
    assert_eq!(generated.body.provenance.dataset_sha256, dataset.sha256());
    verify_reproducible(&generated.body, &dataset).expect("pinned-major replay");
}

#[test]
fn many_seeds_remain_valid_and_decorrelated() {
    let dataset = dataset();
    let template = request();
    let mut profile_ids = BTreeSet::new();
    let mut device_ids = BTreeSet::new();

    for marker in 0_u8..=127 {
        let mut request = template.clone();
        request.seed = STANDARD.encode([marker; 32]);
        let generated = generate(&request, &dataset).expect("seed must generate");
        let report = validate(&generated.body, &dataset);
        assert!(report.valid, "seed {marker}: {:?}", report.issues);
        assert!(profile_ids.insert(generated.body.profile_id));
        assert!(device_ids.insert(generated.body.media.devices[0].device_id.clone()));
    }
    assert_eq!(profile_ids.len(), 128);
    assert_eq!(device_ids.len(), 128);

    for region in dataset.locale_by_region().keys() {
        for class in [DeviceClass::Desktop, DeviceClass::Laptop] {
            let mut request = template.clone();
            request.persona.region.clone_from(region);
            request.persona.device.class = class;
            let generated = generate(&request, &dataset)
                .unwrap_or_else(|error| panic!("{region}/{class:?}: {error}"));
            let report = validate(&generated.body, &dataset);
            assert!(report.valid, "{region}/{class:?}: {:?}", report.issues);
            verify_reproducible(&generated.body, &dataset)
                .unwrap_or_else(|error| panic!("{region}/{class:?}: {error}"));
        }
    }
}

#[test]
fn sign_verify_and_semantic_ingest_round_trip() {
    let dataset = dataset();
    let body = generate(&request(), &dataset).expect("generate").body;
    let key = signing_key();
    let signed = sign_config(body.clone(), &key, Some("proteus-m1a-test-key")).expect("sign");
    let bytes = signed.to_json_pretty().expect("serialize signed config");
    let mut trust = TrustStore::new();
    trust
        .insert("proteus-m1a-test-key", key.verifying_key())
        .expect("trust key");

    let verified = verify_and_validate_signed_json(&bytes, &trust, &dataset)
        .expect("verify and validate exact emitted bytes");
    assert_eq!(verified.body, body);
    assert_eq!(verified.signature, signed.signature);
}

#[test]
fn trusted_but_non_derived_config_fails_deterministic_replay() {
    let dataset = dataset();
    let key = signing_key();
    let mut body = generate(&request(), &dataset).expect("generate").body;
    body.network.quic_policy = QuicPolicy::DisableCoherently;

    assert!(matches!(
        verify_reproducible(&body, &dataset),
        Err(FingerprintError::DeterministicMismatch(path))
            if path == "$.network.quicPolicy"
    ));

    let signed =
        sign_config(body, &key, Some("proteus-m1a-test-key")).expect("authorize modified config");
    let mut trust = TrustStore::new();
    trust
        .insert("proteus-m1a-test-key", key.verifying_key())
        .expect("trust key");
    assert!(matches!(
        verify_and_validate_signed_json(
            &signed.to_json_pretty().expect("serialize"),
            &trust,
            &dataset
        ),
        Err(FingerprintError::DeterministicMismatch(path))
            if path == "$.network.quicPolicy"
    ));
}

#[test]
fn tampering_wrong_keys_and_missing_signatures_fail_closed() {
    let dataset = dataset();
    let key = signing_key();
    let signed = sign_config(
        generate(&request(), &dataset).expect("generate").body,
        &key,
        Some("proteus-m1a-test-key"),
    )
    .expect("sign");
    let mut trust = TrustStore::new();
    trust
        .insert("proteus-m1a-test-key", key.verifying_key())
        .expect("trust key");
    assert!(matches!(
        trust.insert("proteus-m1a-test-key", key.verifying_key()),
        Err(FingerprintError::InvalidSignatureEnvelope(message))
            if message.contains("duplicate trust-store keyId")
    ));
    trust
        .insert("same-key-alias", key.verifying_key())
        .expect("a distinct bound alias may route to the same key");
    let mut aliased = signed.clone();
    aliased.signature.key_id = "same-key-alias".into();
    assert!(matches!(
        verify_signed_json(&aliased.to_json_pretty().expect("serialize alias"), &trust),
        Err(FingerprintError::SignatureVerification)
    ));

    let mut tampered = signed.to_value().expect("signed value");
    tampered["locale"]["timezone"] = serde_json::Value::String("Europe/Berlin".into());
    let error = verify_signed_json(
        &serde_json::to_vec(&tampered).expect("serialize tamper"),
        &trust,
    )
    .expect_err("tamper must fail");
    assert!(matches!(error, FingerprintError::SignatureVerification));

    let mut omitted_nulls = signed.to_value().expect("signed value");
    omitted_nulls["persona"]["device"]
        .as_object_mut()
        .expect("device object")
        .remove("model");
    omitted_nulls["navigator"]
        .as_object_mut()
        .expect("navigator object")
        .remove("oscpu");
    assert!(matches!(
        verify_signed_json(
            &serde_json::to_vec(&omitted_nulls).expect("serialize omissions"),
            &trust
        ),
        Err(FingerprintError::SignatureVerification)
    ));

    let other_key = SigningKey::from_bytes(&[7; 32]);
    let mut wrong_trust = TrustStore::new();
    wrong_trust
        .insert("proteus-m1a-test-key", other_key.verifying_key())
        .expect("insert wrong key");
    assert!(matches!(
        verify_signed_json(&signed.to_json_pretty().expect("serialize"), &wrong_trust),
        Err(FingerprintError::SignatureVerification)
    ));

    let mut missing = signed.to_value().expect("signed value");
    missing.as_object_mut().expect("object").remove("signature");
    assert!(matches!(
        verify_signed_json(&serde_json::to_vec(&missing).expect("serialize"), &trust),
        Err(FingerprintError::InvalidSignatureEnvelope(_))
    ));
}

#[test]
fn duplicate_keys_unknown_fields_and_unsupported_schema_fail_closed() {
    let dataset = dataset();
    let key = signing_key();
    let signed = sign_config(
        generate(&request(), &dataset).expect("generate").body,
        &key,
        Some("proteus-m1a-test-key"),
    )
    .expect("sign");
    let bytes = signed.to_json_pretty().expect("serialize");
    let mut trust = TrustStore::new();
    trust
        .insert("proteus-m1a-test-key", key.verifying_key())
        .expect("trust key");

    let mut duplicate = br#"{"schemaVersion":"1.0.0","#.to_vec();
    duplicate.extend_from_slice(&bytes[1..]);
    assert!(matches!(
        verify_signed_json(&duplicate, &trust),
        Err(FingerprintError::DuplicateKey(key)) if key == "schemaVersion"
    ));

    let mut unknown = signed.to_value().expect("signed value");
    unknown
        .as_object_mut()
        .expect("object")
        .insert("unexpected".into(), true.into());
    assert!(matches!(
        verify_signed_json(&serde_json::to_vec(&unknown).expect("serialize"), &trust),
        Err(FingerprintError::SignatureVerification)
    ));

    let mut version_two_body = signed.body.clone();
    version_two_body.schema_version = "2.0.0".into();
    let version_two = sign_config(version_two_body, &key, Some("proteus-m1a-test-key"))
        .expect("sign unsupported schema");
    assert!(matches!(
        verify_signed_json(
            &version_two.to_json_pretty().expect("serialize"),
            &trust
        ),
        Err(FingerprintError::UnsupportedSchema(version)) if version == "2.0.0"
    ));

    let mut unknown_revision_body = signed.body.clone();
    unknown_revision_body.schema_version = "1.1.0".into();
    let unknown_revision = sign_config(unknown_revision_body, &key, Some("proteus-m1a-test-key"))
        .expect("sign unknown schema revision");
    assert!(matches!(
        verify_signed_json(
            &unknown_revision.to_json_pretty().expect("serialize"),
            &trust
        ),
        Err(FingerprintError::UnsupportedSchema(version)) if version == "1.1.0"
    ));
}

#[test]
fn deterministic_signing_vector_is_stable() {
    let dataset = dataset();
    let body = generate(&request(), &dataset).expect("generate").body;
    let key = signing_key();
    let signed = sign_config(body.clone(), &key, Some("proteus-m1a-test-key")).expect("sign");

    let payload_hash = hex(Sha256::digest(
        canonical_payload(&body).expect("canonical payload"),
    ));
    let input_hash = hex(Sha256::digest(
        signing_input(&body, "proteus-m1a-test-key").expect("signing input"),
    ));
    let public_key = STANDARD.encode(key.verifying_key().to_bytes());

    // These values deliberately form a cross-language conformance vector.
    // Update only with an explicit schema/canonicalization version change.
    assert_eq!(
        payload_hash,
        "19bf3241b393b2c6bef029859645d5f95294bc1c19f04ebb420cb5a77c2d50dc"
    );
    assert_eq!(
        input_hash,
        "3777747e2b3c0762833364f1692199d0b7fcf5171c069257c5a51026ba073d64"
    );
    assert_eq!(public_key, "uvxxvq06xeS2PpyCFu5xo0quxlci7tvKcotOmzzM45Y=");
    assert_eq!(
        signed.signature.value,
        "65XIfDi+hORSjpfkGzZ2gcje9ry4VQANcAoihudJvRpyx7iO9H9Nzpe4qqX4HQE5/w/qiLLDtKA5zXhz5zGCBw=="
    );

    let golden: serde_json::Value = serde_json::from_slice(
        &read(repo_path(
            "fingerprint/conformance/v1/golden/windows-chrome-us.signed.json",
        ))
        .expect("read golden config"),
    )
    .expect("parse golden config");
    assert_eq!(signed.to_value().expect("signed value"), golden);
}

#[test]
fn impossible_or_malformed_requests_are_rejected_without_fallback() {
    let dataset = dataset();
    let mut unsupported = request();
    unsupported.engine.major_version = 999;
    assert!(matches!(
        generate(&unsupported, &dataset),
        Err(FingerprintError::NoCandidate(_))
    ));

    let mut missing_major = serde_json::to_value(request()).expect("request value");
    missing_major["engine"]
        .as_object_mut()
        .expect("engine object")
        .remove("majorVersion");
    assert!(
        serde_json::from_value::<GenerateRequest>(missing_major).is_err(),
        "majorVersion must be an explicit deterministic-generation input"
    );

    let mut bad_seed = request();
    bad_seed.seed = STANDARD.encode([0_u8; 31]);
    assert!(matches!(
        generate(&bad_seed, &dataset),
        Err(FingerprintError::InvalidRequest(_))
    ));

    let mut wrong_arch = request();
    wrong_arch.persona.os.arch = CpuArch::Arm64;
    assert!(matches!(
        generate(&wrong_arch, &dataset),
        Err(FingerprintError::NoCandidate(_))
    ));

    let mut wrong_os_version = request();
    wrong_os_version.persona.os.version = "banana".into();
    assert!(matches!(
        generate(&wrong_os_version, &dataset),
        Err(FingerprintError::NoCandidate(_))
    ));

    let mut modeled_desktop = request();
    modeled_desktop.persona.device.model = Some("not-a-desktop-model".into());
    assert!(matches!(
        generate(&modeled_desktop, &dataset),
        Err(FingerprintError::NoCandidate(_))
    ));
}

#[test]
fn malformed_dataset_cannot_authorize_schema_invalid_screen_dpr() {
    let dataset_bytes =
        read(repo_path("verify-lab/data/reference.json")).expect("read shared seed dataset");
    let mut raw: serde_json::Value =
        serde_json::from_slice(&dataset_bytes).expect("parse shared seed dataset as JSON");
    raw["screenTuplesByClass"]["desktop"][0]["dpr"] = serde_json::json!(0.1);
    assert!(matches!(
        Dataset::from_json(&serde_json::to_vec(&raw).expect("serialize malformed dataset")),
        Err(FingerprintError::InvalidDataset(message))
            if message.contains("violates Profile Config numeric bounds")
    ));

    let valid_dataset = dataset();

    let key = signing_key();
    let mut body = generate(&request(), &valid_dataset)
        .expect("generate valid baseline")
        .body;
    body.screen.device_pixel_ratio = 0.1;
    let signed =
        sign_config(body, &key, Some("proteus-m1a-test-key")).expect("sign malformed config");
    let mut trust = TrustStore::new();
    trust
        .insert("proteus-m1a-test-key", key.verifying_key())
        .expect("trust key");
    assert!(matches!(
        verify_and_validate_signed_json(
            &signed.to_json_pretty().expect("serialize"),
            &trust,
            &valid_dataset,
        ),
        Err(FingerprintError::Validation(message))
            if message.contains("screen.devicePixelRatio")
    ));
}

#[test]
fn schema_valid_generation_domain_is_always_canonicalizable() {
    let dataset_bytes =
        read(repo_path("verify-lab/data/reference.json")).expect("read shared seed dataset");
    let mut raw: serde_json::Value =
        serde_json::from_slice(&dataset_bytes).expect("parse shared seed dataset as JSON");
    raw["screenTuplesByClass"]["desktop"][0]["dpr"] = serde_json::json!(1e21);
    assert!(matches!(
        Dataset::from_json(&serde_json::to_vec(&raw).expect("serialize malformed dataset")),
        Err(FingerprintError::InvalidDataset(message))
            if message.contains("violates Profile Config numeric bounds")
    ));

    let mut body = generate(&request(), &dataset())
        .expect("generate valid baseline")
        .body;
    body.rarity.score = 1e-7;
    let report = validate(&body, &dataset());
    assert!(
        report
            .issues
            .iter()
            .any(|issue| issue.rule_id == "R-RARITY-RANGE"),
        "sub-canonical nonzero rarity scores must fail before signing"
    );
}

#[test]
fn replay_region_mapping_must_be_bidirectionally_consistent() {
    let dataset_bytes =
        read(repo_path("verify-lab/data/reference.json")).expect("read shared seed dataset");
    let mut raw: serde_json::Value =
        serde_json::from_slice(&dataset_bytes).expect("parse shared seed dataset as JSON");
    raw["timezoneToRegion"]["America/New_York"] = serde_json::json!("DE");
    assert!(matches!(
        Dataset::from_json(&serde_json::to_vec(&raw).expect("serialize malformed dataset")),
        Err(FingerprintError::InvalidDataset(message))
            if message.contains("does not reverse-map")
    ));
}

#[test]
fn strict_validator_covers_schema_bounds_not_expressed_by_rust_types() {
    let dataset = dataset();
    let mut body = generate(&request(), &dataset)
        .expect("generate baseline")
        .body;
    body.engine.major_version = 0;
    body.engine.full_version = "not-a-version".into();
    body.navigator.languages.clear();
    body.navigator.hardware_concurrency = 0;
    body.navigator.device_memory = f64::NAN;
    let hints = body.client_hints.as_mut().expect("Chromium Client Hints");
    hints.brands.clear();
    hints.full_version_list.clear();
    body.screen.width = 0;
    body.screen.color_depth = 8;
    body.screen.device_pixel_ratio = 0.1;
    body.fonts.set.clear();
    body.media.devices.clear();
    body.media.speech_voices.clear();
    body.performance.timer_precision_micros = 0;
    body.provenance.dataset_sha256 = "ABC".into();

    let report = validate(&body, &dataset);
    assert!(!report.valid);
    let schema_fields = report
        .issues
        .iter()
        .filter(|issue| issue.rule_id == "R-CONFIG-SCHEMA")
        .flat_map(|issue| issue.fields.iter().map(String::as_str))
        .collect::<BTreeSet<_>>();
    for expected in [
        "engine.majorVersion",
        "engine.fullVersion",
        "navigator.languages",
        "navigator.hardwareConcurrency",
        "navigator.deviceMemory",
        "clientHints.brands",
        "clientHints.fullVersionList",
        "screen.width",
        "screen.colorDepth",
        "screen.devicePixelRatio",
        "fonts.set",
        "media.devices",
        "media.speechVoices",
        "performance.timerPrecisionMicros",
        "provenance.datasetSha256",
    ] {
        assert!(
            schema_fields.contains(expected),
            "missing strict schema issue for {expected}: {:?}",
            report.issues
        );
    }
}

fn hex(bytes: impl AsRef<[u8]>) -> String {
    let mut result = String::new();
    for byte in bytes.as_ref() {
        use std::fmt::Write as _;
        write!(&mut result, "{byte:02x}").expect("write hex");
    }
    result
}
