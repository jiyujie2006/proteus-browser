use std::collections::BTreeSet;
use std::fs::read;
use std::path::PathBuf;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use ed25519_dalek::SigningKey;
use proteus_fingerprint::model::{CpuArch, DeviceClass, OsName, QuicPolicy};
use proteus_fingerprint::{
    Dataset, FingerprintError, GENERATOR_VERSION, GenerateRequest, RULES_VERSION, TrustStore,
    canonical_payload, generate, rescore, sign_config, signing_input, validate,
    verify_and_validate_signed_json, verify_reproducible, verify_signed_json,
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
    assert_eq!(dataset.version(), "0.3.0");
    assert_eq!(
        dataset.sha256(),
        "022919ecb9b990f17570bb0793c74871cfca393b0177e5cd5e098094e3d95787"
    );
    assert_eq!(dataset.rules_version(), "1.1.0");
    assert_eq!(dataset.rules_version(), RULES_VERSION);
    assert_eq!(GENERATOR_VERSION, "0.2.0");
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
fn generated_ua_and_client_hints_exactly_match_the_pinned_chrome_target() {
    let dataset = dataset();
    let body = generate(&request(), &dataset)
        .expect("generate exact target")
        .body;
    let target = dataset
        .engine_targets()
        .iter()
        .find(|target| {
            target.family == "chromium" && target.brand == "Chrome" && target.major_version == 150
        })
        .expect("Chrome 150 target");
    let hints = body.client_hints.as_ref().expect("Chromium Client Hints");

    assert_eq!(
        body.navigator.user_agent,
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
         (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36"
    );
    assert!(
        !body
            .navigator
            .user_agent
            .contains(&body.engine.full_version),
        "the reduced UA must not leak the full patch version"
    );
    assert_eq!(hints.brands, target.client_hint_brands);
    assert_eq!(
        hints.full_version_list,
        target.client_hint_full_version_list
    );
    assert_eq!(
        hints.brands[0],
        proteus_fingerprint::model::BrandVersion {
            brand: "Not;A=Brand".into(),
            version: "8".into(),
        }
    );
    assert_eq!(
        hints.full_version_list[0],
        proteus_fingerprint::model::BrandVersion {
            brand: "Not;A=Brand".into(),
            version: "8.0.0.0".into(),
        }
    );
}

#[test]
fn explicit_major_stays_replayable_and_rescorable_with_multiple_dataset_targets() {
    let original = dataset();
    let dataset_bytes =
        read(repo_path("verify-lab/data/reference.json")).expect("read shared seed dataset");
    let mut raw: serde_json::Value =
        serde_json::from_slice(&dataset_bytes).expect("parse shared seed dataset as JSON");
    let mut alternate = raw["engineTargets"][0].clone();
    alternate["majorVersion"] = serde_json::json!(149);
    alternate["fullVersion"] = serde_json::json!("149.0.0.0");
    alternate["weight"] = serde_json::json!(u32::MAX);
    alternate["clientHintBrands"][1]["version"] = serde_json::json!("149");
    alternate["clientHintBrands"][2]["version"] = serde_json::json!("149");
    alternate["clientHintFullVersionList"][1]["version"] = serde_json::json!("149.0.0.0");
    alternate["clientHintFullVersionList"][2]["version"] = serde_json::json!("149.0.0.0");
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
    assert_eq!(
        rescore(&generated.body, &dataset).expect("rescore pinned-major profile"),
        generated.body.rarity,
        "an unrelated high-weight engine major must not change the pinned target's rarity"
    );
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

    // These values deliberately form the current cross-language conformance
    // vector. Behavior/provenance changes create a new versioned directory;
    // older vector bytes remain immutable.
    assert_eq!(
        payload_hash,
        "c82c6d94e2dd858c04e1b7872f5fd7f50b662b9666f5874347c461af1c16df95"
    );
    assert_eq!(
        input_hash,
        "b9029ea3209bcde6f356e8c61ed29843ba65588c692371ac8ae5409209fc08e2"
    );
    assert_eq!(public_key, "uvxxvq06xeS2PpyCFu5xo0quxlci7tvKcotOmzzM45Y=");
    assert_eq!(
        signed.signature.value,
        "mCMU//o6bcyJtAjrJkYdcYgwGTj410mXlFeWiWmc3eXmPLRrBNAcShKVJr70eUyHGnNBA24H4Q2q5aGde3/qCg=="
    );

    let golden: serde_json::Value = serde_json::from_slice(
        &read(repo_path(
            "fingerprint/conformance/v2/golden/windows-chrome-us.signed.json",
        ))
        .expect("read golden config"),
    )
    .expect("parse golden config");
    assert_eq!(signed.to_value().expect("signed value"), golden);
}

#[test]
fn legacy_conformance_v1_bytes_and_signature_remain_valid() {
    let golden = read(repo_path(
        "fingerprint/conformance/v1/golden/windows-chrome-us.signed.json",
    ))
    .expect("read legacy golden");
    let vector = read(repo_path("fingerprint/conformance/v1/signing-vector.json"))
        .expect("read legacy vector");
    assert_eq!(
        hex(Sha256::digest(&golden)),
        "f29dcf0e7d36cf18054c6591de3742d46feca8bb72da6c5d8112de9690529417"
    );
    assert_eq!(
        hex(Sha256::digest(&vector)),
        "79486a75d3658114c6864b6a4a43f581eba02db7b5ad698bd18d06e8bc290178"
    );

    let key = signing_key();
    let mut trust = TrustStore::new();
    trust
        .insert("proteus-m1a-test-key", key.verifying_key())
        .expect("trust legacy signing key");
    verify_signed_json(&golden, &trust).expect("legacy v1 signature remains verifiable");
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
fn strict_validator_rejects_personas_outside_the_m1a_target() {
    let dataset = dataset();
    let baseline = generate(&request(), &dataset)
        .expect("generate valid baseline")
        .body;

    let mut wrong_os = baseline.clone();
    wrong_os.persona.os.name = OsName::Linux;
    let mut wrong_version = baseline.clone();
    wrong_version.persona.os.version = "banana".into();
    let mut wrong_arch = baseline.clone();
    wrong_arch.persona.os.arch = CpuArch::Arm64;
    let mut wrong_class = baseline.clone();
    wrong_class.persona.device.class = DeviceClass::Phone;
    let mut modeled_desktop = baseline;
    modeled_desktop.persona.device.model = Some("not-a-desktop-model".into());

    for (case, config, expected_field) in [
        ("OS", wrong_os, "persona.os.name"),
        ("OS version", wrong_version, "persona.os.version"),
        ("architecture", wrong_arch, "persona.os.arch"),
        ("device class", wrong_class, "persona.device.class"),
        ("device model", modeled_desktop, "persona.device.model"),
    ] {
        let report = validate(&config, &dataset);
        assert!(!report.valid, "{case} mutation must be rejected");
        assert!(
            report.issues.iter().any(|issue| {
                issue.rule_id == "R-PERSONA-TARGET"
                    && issue.fields == [expected_field]
                    && issue.reason.contains("M1A")
            }),
            "{case} mutation needs a structured R-PERSONA-TARGET issue: {:?}",
            report.issues
        );
    }
}

#[test]
fn strict_validator_rejects_unbound_client_hints_platform_version() {
    let dataset = dataset();
    let mut body = generate(&request(), &dataset)
        .expect("generate valid baseline")
        .body;
    body.client_hints
        .as_mut()
        .expect("Chromium Client Hints")
        .platform_version = "0.0.0".into();

    let report = validate(&body, &dataset);
    assert!(!report.valid);
    assert!(
        report.issues.iter().any(|issue| {
            issue.rule_id == "R-UA-CH"
                && issue
                    .fields
                    .iter()
                    .any(|field| field == "clientHints.platformVersion")
                && issue.reason.contains("engine target value")
        }),
        "platformVersion mutation needs a structured R-UA-CH issue: {:?}",
        report.issues
    );
}

#[test]
fn strict_validator_rejects_a_mobile_model_for_the_windows_desktop_target() {
    let dataset = dataset();
    let mut body = generate(&request(), &dataset)
        .expect("generate valid baseline")
        .body;
    body.client_hints
        .as_mut()
        .expect("Chromium Client Hints")
        .model = "Pixel 10".into();

    let report = validate(&body, &dataset);
    assert!(!report.valid);
    assert!(
        report.issues.iter().any(|issue| {
            issue.rule_id == "R-UA-CH"
                && issue
                    .fields
                    .iter()
                    .any(|field| field == "clientHints.model")
                && issue.reason.contains("must be empty")
        }),
        "Client Hints model mutation needs a structured R-UA-CH issue: {:?}",
        report.issues
    );
}

#[test]
fn strict_validator_rejects_any_drift_in_ua_ch_webgl_or_screen_records() {
    let dataset = dataset();
    let baseline = generate(&request(), &dataset)
        .expect("generate valid baseline")
        .body;

    let mut full_version_ua = baseline.clone();
    full_version_ua.navigator.user_agent = format!(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
         (KHTML, like Gecko) Chrome/{} Safari/537.36",
        full_version_ua.engine.full_version
    );
    let mut reordered_brands = baseline.clone();
    reordered_brands
        .client_hints
        .as_mut()
        .expect("Client Hints")
        .brands
        .swap(0, 1);
    let mut changed_full_list = baseline.clone();
    changed_full_list
        .client_hints
        .as_mut()
        .expect("Client Hints")
        .full_version_list[0]
        .version = "99.0.0.0".into();
    let mut changed_extensions = baseline.clone();
    changed_extensions.gpu.webgl_extensions.swap(0, 1);
    let mut changed_available_screen = baseline.clone();
    changed_available_screen.screen.avail_height -= 1;
    let mut approximate_dpr = baseline;
    approximate_dpr.screen.device_pixel_ratio += 0.0005;

    for (case, config, rule, field) in [
        (
            "unreduced UA",
            full_version_ua,
            "R-UA-CH",
            "navigator.userAgent",
        ),
        (
            "reordered brands",
            reordered_brands,
            "R-UA-CH",
            "clientHints.brands",
        ),
        (
            "changed full-version list",
            changed_full_list,
            "R-UA-CH",
            "clientHints.fullVersionList",
        ),
        (
            "changed WebGL extensions",
            changed_extensions,
            "R-WEBGL-WEBGPU",
            "gpu.webglExtensions",
        ),
        (
            "changed available screen",
            changed_available_screen,
            "R-SCREEN-REAL",
            "screen",
        ),
        (
            "approximately matching DPR",
            approximate_dpr,
            "R-SCREEN-REAL",
            "screen",
        ),
    ] {
        let report = validate(&config, &dataset);
        assert!(!report.valid, "{case} mutation must be rejected");
        assert!(
            report.issues.iter().any(|issue| {
                issue.rule_id == rule && issue.fields.iter().any(|path| path == field)
            }),
            "{case} needs a structured {rule} issue for {field}: {:?}",
            report.issues
        );
    }
}

#[test]
fn gpu_profiles_are_conditioned_on_device_class_for_generation_and_validation() {
    let dataset = dataset();
    let mut laptop_request = request();
    laptop_request.persona.device.class = DeviceClass::Laptop;
    for marker in 0_u8..=63 {
        laptop_request.seed = STANDARD.encode([marker; 32]);
        let body = generate(&laptop_request, &dataset)
            .unwrap_or_else(|error| panic!("laptop seed {marker}: {error}"))
            .body;
        let profile = dataset.gpu_profiles_by_os()["Windows"]
            .iter()
            .find(|profile| {
                profile.webgl_vendor == body.gpu.webgl_vendor
                    && profile.webgl_renderer == body.gpu.webgl_renderer
            })
            .expect("generated GPU belongs to the Windows table");
        assert!(
            profile
                .allowed_device_classes
                .contains(&DeviceClass::Laptop),
            "laptop generation selected a desktop-only GPU"
        );
    }

    let mut desktop_only_gpu_on_laptop = generate(&request(), &dataset)
        .expect("the fixed desktop seed selects a desktop GPU")
        .body;
    let selected = dataset.gpu_profiles_by_os()["Windows"]
        .iter()
        .find(|profile| {
            profile.webgl_renderer == desktop_only_gpu_on_laptop.gpu.webgl_renderer
                && profile.webgl_vendor == desktop_only_gpu_on_laptop.gpu.webgl_vendor
        })
        .expect("selected GPU profile");
    assert!(
        !selected
            .allowed_device_classes
            .contains(&DeviceClass::Laptop),
        "fixture seed must exercise a desktop-only GPU"
    );
    desktop_only_gpu_on_laptop.persona.device.class = DeviceClass::Laptop;
    let report = validate(&desktop_only_gpu_on_laptop, &dataset);
    assert!(
        report.issues.iter().any(|issue| {
            issue.rule_id == "R-PLATFORM-GPU"
                && issue
                    .fields
                    .iter()
                    .any(|field| field == "persona.device.class")
        }),
        "OS+class-invalid GPU needs R-PLATFORM-GPU: {:?}",
        report.issues
    );
}

#[test]
fn strict_validator_compares_every_webgpu_adapter_field() {
    let dataset = dataset();
    let baseline = generate(&request(), &dataset)
        .expect("generate valid baseline")
        .body;

    let mut wrong_architecture = baseline.clone();
    wrong_architecture
        .gpu
        .webgpu_adapter
        .as_mut()
        .expect("WebGPU adapter")
        .architecture = "wrong-architecture".into();
    let mut wrong_description = baseline;
    wrong_description
        .gpu
        .webgpu_adapter
        .as_mut()
        .expect("WebGPU adapter")
        .description = "wrong description".into();

    for (field, config) in [
        ("architecture", wrong_architecture),
        ("description", wrong_description),
    ] {
        let report = validate(&config, &dataset);
        assert!(!report.valid, "WebGPU {field} mutation must be rejected");
        assert!(
            report.issues.iter().any(|issue| {
                issue.rule_id == "R-WEBGL-WEBGPU"
                    && issue.fields.iter().any(|path| path == "gpu.webgpuAdapter")
                    && issue.reason.contains("exactly match")
            }),
            "WebGPU {field} mutation needs an R-WEBGL-WEBGPU issue: {:?}",
            report.issues
        );
    }
}

#[test]
fn rescore_requires_the_complete_class_eligible_gpu_record() {
    let dataset = dataset();
    let baseline = generate(&request(), &dataset)
        .expect("generate valid baseline")
        .body;

    let mut changed_extensions = baseline.clone();
    changed_extensions.gpu.webgl_extensions.swap(0, 1);
    assert!(matches!(
        rescore(&changed_extensions, &dataset),
        Err(FingerprintError::NoCandidate(message))
            if message.contains("GPU profile")
    ));

    let mut changed_adapter = baseline;
    changed_adapter
        .gpu
        .webgpu_adapter
        .as_mut()
        .expect("WebGPU adapter")
        .description = "same renderer, different adapter record".into();
    assert!(matches!(
        rescore(&changed_adapter, &dataset),
        Err(FingerprintError::NoCandidate(message))
            if message.contains("GPU profile")
    ));
}

#[test]
fn chrome_150_non_android_device_memory_buckets_accept_16_and_32_gib_joint_pairs() {
    let dataset = dataset();
    let desktop = generate(&request(), &dataset)
        .expect("generate desktop baseline")
        .body;
    let mut laptop_request = request();
    laptop_request.persona.device.class = DeviceClass::Laptop;
    let laptop = generate(&laptop_request, &dataset)
        .expect("generate laptop baseline")
        .body;

    for (case, mut body, cores, memory) in [
        ("desktop 16/16", desktop.clone(), 16, 16.0),
        ("desktop 32/32", desktop, 32, 32.0),
        ("laptop 16/16", laptop, 16, 16.0),
    ] {
        body.navigator.hardware_concurrency = cores;
        body.navigator.device_memory = memory;
        let report = validate(&body, &dataset);
        assert!(
            report.valid,
            "{case} is a declared Chrome 150 joint pair and must pass public semantic validation: {:?}",
            report.issues
        );
    }
}

#[test]
fn dataset_rejects_semantically_duplicate_or_unbound_sampling_records() {
    let bytes =
        read(repo_path("verify-lab/data/reference.json")).expect("read shared seed dataset");
    let baseline: serde_json::Value =
        serde_json::from_slice(&bytes).expect("parse shared seed dataset as JSON");

    let mut duplicate_target = baseline.clone();
    let target = duplicate_target["engineTargets"][0].clone();
    duplicate_target["engineTargets"]
        .as_array_mut()
        .expect("engine target array")
        .push(target);
    assert_invalid_dataset(duplicate_target, "duplicate semantic engine target");

    let mut wrong_target_family = baseline.clone();
    wrong_target_family["engineTargets"][0]["family"] = serde_json::json!("firefox");
    assert_invalid_dataset(wrong_target_family, "belongs to chromium");

    let mut duplicate_gpu = baseline.clone();
    let gpu = duplicate_gpu["gpuProfilesByOs"]["Windows"][0].clone();
    duplicate_gpu["gpuProfilesByOs"]["Windows"]
        .as_array_mut()
        .expect("GPU profile array")
        .push(gpu);
    assert_invalid_dataset(duplicate_gpu, "duplicate semantic WebGL GPU profile");

    let mut duplicate_gpu_class = baseline.clone();
    duplicate_gpu_class["gpuProfilesByOs"]["Windows"][0]["allowedDeviceClasses"]
        .as_array_mut()
        .expect("allowed classes")
        .push(serde_json::json!("desktop"));
    assert_invalid_dataset(duplicate_gpu_class, "unique allowedDeviceClasses");

    let mut duplicate_extension = baseline.clone();
    let extension =
        duplicate_extension["gpuProfilesByOs"]["Windows"][0]["webglExtensions"][0].clone();
    duplicate_extension["gpuProfilesByOs"]["Windows"][0]["webglExtensions"]
        .as_array_mut()
        .expect("WebGL extensions")
        .push(extension);
    assert_invalid_dataset(duplicate_extension, "unique WebGL extensions");

    let mut duplicate_screen = baseline.clone();
    let screen = duplicate_screen["screenTuplesByClass"]["desktop"][0].clone();
    duplicate_screen["screenTuplesByClass"]["desktop"]
        .as_array_mut()
        .expect("screen tuple array")
        .push(screen);
    assert_invalid_dataset(duplicate_screen, "duplicate semantic tuple");

    let mut unbound_screen_weight = baseline.clone();
    unbound_screen_weight["screenWeightsByClass"]["desktop"]["111x222@1"] = serde_json::json!(1);
    assert_invalid_dataset(unbound_screen_weight, "must exactly match");

    let mut duplicate_hardware = baseline.clone();
    let hardware = duplicate_hardware["hardwarePairsByClass"]["desktop"][0].clone();
    duplicate_hardware["hardwarePairsByClass"]["desktop"]
        .as_array_mut()
        .expect("hardware pair array")
        .push(hardware);
    assert_invalid_dataset(duplicate_hardware, "duplicate semantic pair");

    let mut duplicate_font = baseline.clone();
    let font = duplicate_font["fontProfilesByOs"]["Windows"][0].clone();
    duplicate_font["fontProfilesByOs"]["Windows"]
        .as_array_mut()
        .expect("font profile array")
        .push(font);
    assert_invalid_dataset(duplicate_font, "unique IDs/sets");

    let mut duplicate_media = baseline.clone();
    let media = duplicate_media["mediaProfilesByOs"]["Windows"][0].clone();
    duplicate_media["mediaProfilesByOs"]["Windows"]
        .as_array_mut()
        .expect("media profile array")
        .push(media);
    assert_invalid_dataset(duplicate_media, "unique non-empty IDs");

    let mut unbound_client_hints = baseline;
    unbound_client_hints["engineTargets"][0]["clientHintBrands"][2]["version"] =
        serde_json::json!("149");
    unbound_client_hints["engineTargets"][0]["clientHintFullVersionList"][2]["version"] =
        serde_json::json!("149.0.0.0");
    assert_invalid_dataset(
        unbound_client_hints,
        "must bind Chromium/product versions and exactly one GREASE brand",
    );

    let mut extra_client_hint = serde_json::from_slice::<serde_json::Value>(&bytes)
        .expect("parse shared seed dataset as JSON");
    extra_client_hint["engineTargets"][0]["clientHintBrands"]
        .as_array_mut()
        .expect("Client Hint brands")
        .push(serde_json::json!({ "brand": "Arbitrary Browser", "version": "1" }));
    extra_client_hint["engineTargets"][0]["clientHintFullVersionList"]
        .as_array_mut()
        .expect("Client Hint full-version list")
        .push(serde_json::json!({ "brand": "Arbitrary Browser", "version": "1.0.0.0" }));
    assert_invalid_dataset(
        extra_client_hint,
        "exactly three aligned Client Hint entries",
    );
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

fn assert_invalid_dataset(raw: serde_json::Value, expected: &str) {
    assert!(
        matches!(
            Dataset::from_json(&serde_json::to_vec(&raw).expect("serialize malformed dataset")),
            Err(FingerprintError::InvalidDataset(message)) if message.contains(expected)
        ),
        "dataset mutation should fail with a message containing {expected:?}"
    );
}

fn hex(bytes: impl AsRef<[u8]>) -> String {
    let mut result = String::new();
    for byte in bytes.as_ref() {
        use std::fmt::Write as _;
        write!(&mut result, "{byte:02x}").expect("write hex");
    }
    result
}
