use std::collections::BTreeSet;

use base64::{Engine as _, engine::general_purpose::STANDARD};

use crate::GENERATOR_VERSION;
use crate::dataset::Dataset;
use crate::model::{
    BrowserBrand, ConfigBody, CpuArch, DeviceClass, EngineFamily, NoiseAmplitude, OsName,
    RarityVerdict, ValidationIssue, ValidationReport,
};
use crate::schema_contract::{
    is_canonical_f64, is_full_version, is_lower_hex_sha256, is_media_device_kind, is_seed,
};

/// Strict generation-time semantic validator. Missing or unknown values fail;
/// unlike a runtime observation probe, this mode never turns uncertainty into NA.
pub fn validate(config: &ConfigBody, dataset: &Dataset) -> ValidationReport {
    let mut issues = Vec::new();
    let mut fail = |rule_id: &str, fields: &[&str], reason: String| {
        issues.push(ValidationIssue {
            rule_id: rule_id.into(),
            fields: fields.iter().map(|field| (*field).into()).collect(),
            reason,
        });
    };

    if config.schema_version != crate::generator::PROFILE_SCHEMA_VERSION {
        fail(
            "R-CONFIG-SCHEMA",
            &["schemaVersion"],
            format!("unsupported schema version {}", config.schema_version),
        );
    }
    if !is_uuid(&config.profile_id) {
        fail(
            "R-CONFIG-PROFILE-ID",
            &["profileId"],
            "profileId is not an RFC 4122 UUID".into(),
        );
    }
    if !is_seed(&config.seed) {
        fail(
            "R-CONFIG-SEED",
            &["seed"],
            "seed does not match the strict 32-byte standard-base64 schema pattern".into(),
        );
    } else {
        match STANDARD.decode(&config.seed) {
            Ok(seed) if seed.len() == 32 => {}
            Ok(seed) => fail(
                "R-CONFIG-SEED",
                &["seed"],
                format!("seed decodes to {} bytes instead of 32", seed.len()),
            ),
            Err(error) => fail(
                "R-CONFIG-SEED",
                &["seed"],
                format!("seed is not valid standard base64: {error}"),
            ),
        }
    }

    if config.persona.os.name != OsName::Windows {
        fail(
            "R-PERSONA-TARGET",
            &["persona.os.name"],
            "M1A supports Windows personas only".into(),
        );
    }
    if config.persona.os.version != "11" {
        fail(
            "R-PERSONA-TARGET",
            &["persona.os.version"],
            "M1A requires persona.os.version to be Windows 11".into(),
        );
    }
    if config.persona.os.arch != CpuArch::X86_64 {
        fail(
            "R-PERSONA-TARGET",
            &["persona.os.arch"],
            "M1A requires the x86_64 CPU architecture".into(),
        );
    }
    if !matches!(
        config.persona.device.class,
        DeviceClass::Desktop | DeviceClass::Laptop
    ) {
        fail(
            "R-PERSONA-TARGET",
            &["persona.device.class"],
            "M1A supports desktop and laptop device classes only".into(),
        );
    }
    if config.persona.device.model.is_some() {
        fail(
            "R-PERSONA-TARGET",
            &["persona.device.model"],
            "M1A requires persona.device.model to be null".into(),
        );
    }

    if config.engine.major_version == 0 {
        fail(
            "R-CONFIG-SCHEMA",
            &["engine.majorVersion"],
            "engine.majorVersion must be at least 1".into(),
        );
    }
    if !is_full_version(&config.engine.full_version) {
        fail(
            "R-CONFIG-SCHEMA",
            &["engine.fullVersion"],
            "engine.fullVersion must contain 2-4 decimal components".into(),
        );
    }
    if config.navigator.languages.is_empty() {
        fail(
            "R-CONFIG-SCHEMA",
            &["navigator.languages"],
            "navigator.languages must contain at least one value".into(),
        );
    }
    if config.navigator.hardware_concurrency == 0 {
        fail(
            "R-CONFIG-SCHEMA",
            &["navigator.hardwareConcurrency"],
            "navigator.hardwareConcurrency must be at least 1".into(),
        );
    }
    if !is_canonical_f64(config.navigator.device_memory)
        || !(0.25..=1024.0).contains(&config.navigator.device_memory)
    {
        fail(
            "R-CONFIG-SCHEMA",
            &["navigator.deviceMemory"],
            "navigator.deviceMemory must be canonical and within [0.25,1024] GiB".into(),
        );
    }
    if let Some(hints) = &config.client_hints {
        if hints.brands.is_empty() {
            fail(
                "R-CONFIG-SCHEMA",
                &["clientHints.brands"],
                "clientHints.brands must contain at least one value".into(),
            );
        }
        if hints.full_version_list.is_empty() {
            fail(
                "R-CONFIG-SCHEMA",
                &["clientHints.fullVersionList"],
                "clientHints.fullVersionList must contain at least one value".into(),
            );
        }
    }
    if config.screen.width == 0
        || config.screen.height == 0
        || config.screen.avail_width == 0
        || config.screen.avail_height == 0
    {
        fail(
            "R-CONFIG-SCHEMA",
            &[
                "screen.width",
                "screen.height",
                "screen.availWidth",
                "screen.availHeight",
            ],
            "screen dimensions must each be at least 1".into(),
        );
    }
    if !matches!(config.screen.color_depth, 24 | 30 | 48) {
        fail(
            "R-CONFIG-SCHEMA",
            &["screen.colorDepth"],
            "screen.colorDepth is not a schema-supported value".into(),
        );
    }
    if !is_canonical_f64(config.screen.device_pixel_ratio)
        || !(0.5..=16.0).contains(&config.screen.device_pixel_ratio)
    {
        fail(
            "R-CONFIG-SCHEMA",
            &["screen.devicePixelRatio"],
            "screen.devicePixelRatio must be canonical and within [0.5,16]".into(),
        );
    }
    if config.fonts.set.is_empty() {
        fail(
            "R-CONFIG-SCHEMA",
            &["fonts.set"],
            "fonts.set must contain at least one value".into(),
        );
    }
    if config.media.devices.is_empty() {
        fail(
            "R-CONFIG-SCHEMA",
            &["media.devices"],
            "media.devices must contain at least one value".into(),
        );
    }
    if config.media.speech_voices.is_empty() {
        fail(
            "R-CONFIG-SCHEMA",
            &["media.speechVoices"],
            "media.speechVoices must contain at least one value".into(),
        );
    }
    if config.media.devices.iter().any(|device| {
        !is_media_device_kind(&device.kind)
            || device.device_id.is_empty()
            || device.group_id.is_empty()
    }) {
        fail(
            "R-CONFIG-SCHEMA",
            &["media.devices"],
            "media devices need a recognized kind and non-empty device/group IDs".into(),
        );
    }
    if config.performance.timer_precision_micros == 0 {
        fail(
            "R-CONFIG-SCHEMA",
            &["performance.timerPrecisionMicros"],
            "performance.timerPrecisionMicros must be at least 1".into(),
        );
    }
    if !is_lower_hex_sha256(&config.provenance.dataset_sha256) {
        fail(
            "R-CONFIG-SCHEMA",
            &["provenance.datasetSha256"],
            "provenance.datasetSha256 must be 64 lowercase hexadecimal characters".into(),
        );
    }

    let expected_family = match config.engine.brand {
        BrowserBrand::Firefox => EngineFamily::Firefox,
        _ => EngineFamily::Chromium,
    };
    if config.engine.family != expected_family {
        fail(
            "R-UA-CH",
            &["engine.family", "engine.brand"],
            format!(
                "{} does not belong to {}",
                config.engine.brand.as_str(),
                config.engine.family.as_str()
            ),
        );
    }
    let full_major = config
        .engine
        .full_version
        .split('.')
        .next()
        .and_then(|value| value.parse::<u32>().ok());
    if full_major != Some(config.engine.major_version) {
        fail(
            "R-UA-CH",
            &["engine.majorVersion", "engine.fullVersion"],
            "engine majorVersion and fullVersion disagree".into(),
        );
    }
    let engine_target = dataset.engine_targets.iter().find(|target| {
        target.family == config.engine.family.as_str()
            && target.brand == config.engine.brand.as_str()
            && target.major_version == config.engine.major_version
            && target.full_version == config.engine.full_version
    });
    if engine_target.is_none() {
        fail(
            "R-VERSION-LIVE",
            &["engine"],
            "engine target is not present in the signed seed dataset".into(),
        );
    }
    if let Some(window) = dataset
        .live_version_window
        .get(config.engine.brand.as_str())
    {
        if config.engine.major_version < window.min || config.engine.major_version > window.max {
            fail(
                "R-VERSION-LIVE",
                &["engine.majorVersion"],
                format!(
                    "{} {} is outside live window [{}, {}]",
                    config.engine.brand.as_str(),
                    config.engine.major_version,
                    window.min,
                    window.max
                ),
            );
        }
    } else {
        fail(
            "R-VERSION-LIVE",
            &["engine.brand"],
            "engine brand has no live-version reference".into(),
        );
    }

    let os = config.persona.os.name.as_str();
    let allowed_platforms = dataset.platform_by_os.get(os);
    if !allowed_platforms.is_some_and(|values| values.contains(&config.navigator.platform)) {
        fail(
            "R-PLATFORM-OS",
            &["persona.os.name", "navigator.platform"],
            format!(
                "navigator.platform {} is not allowed for {os}",
                config.navigator.platform
            ),
        );
    }
    if config.persona.os.name == OsName::Windows
        && config.engine.brand == BrowserBrand::Chrome
        && config.navigator.user_agent
            != crate::generator::windows_chrome_user_agent(config.engine.major_version)
    {
        fail(
            "R-UA-CH",
            &[
                "navigator.userAgent",
                "engine.majorVersion",
                "persona.os.name",
            ],
            "UA must exactly match the reduced Windows Chrome major.0.0.0 form".into(),
        );
    }
    let expected_vendor = dataset.vendor_by_family.get(config.engine.family.as_str());
    if expected_vendor != Some(&config.navigator.vendor) {
        fail(
            "R-VENDOR-FAMILY",
            &["navigator.vendor", "engine.family"],
            "navigator.vendor does not match the engine family".into(),
        );
    }

    match (&config.engine.family, &config.client_hints) {
        (EngineFamily::Chromium, None) => fail(
            "R-UA-CH",
            &["clientHints", "engine.family"],
            "Chromium config must include Client Hints".into(),
        ),
        (EngineFamily::Firefox, Some(_)) => fail(
            "R-UA-CH",
            &["clientHints", "engine.family"],
            "Firefox config must encode Client Hints as null".into(),
        ),
        (_, Some(hints)) => {
            let expected_platform = match config.persona.os.name {
                OsName::Windows => "Windows",
                OsName::MacOs => "macOS",
                OsName::Linux => "Linux",
                OsName::ChromeOs => "Chrome OS",
                OsName::Android => "Android",
                OsName::Ios => "iOS",
            };
            if hints.platform != expected_platform {
                fail(
                    "R-UA-CH",
                    &["clientHints.platform", "persona.os.name"],
                    format!(
                        "Client Hints platform {} does not match {expected_platform}",
                        hints.platform
                    ),
                );
            }
            match engine_target.and_then(|target| {
                target
                    .platform_versions
                    .get(config.persona.os.name.as_str())
            }) {
                Some(expected) if hints.platform_version == *expected => {}
                Some(expected) => fail(
                    "R-UA-CH",
                    &["clientHints.platformVersion", "engine", "persona.os.name"],
                    format!(
                        "Client Hints platform version {} does not match engine target value {expected}",
                        hints.platform_version
                    ),
                ),
                None => fail(
                    "R-UA-CH",
                    &["clientHints.platformVersion", "engine", "persona.os.name"],
                    "matching engine target has no platform version for the persona OS".into(),
                ),
            }
            let mobile = matches!(
                config.persona.device.class,
                DeviceClass::Tablet | DeviceClass::Phone
            );
            if hints.mobile != mobile {
                fail(
                    "R-UA-CH",
                    &["clientHints.mobile", "persona.device.class"],
                    "Client Hints mobile flag contradicts device class".into(),
                );
            }
            if let Some(target) = engine_target {
                if hints.brands != target.client_hint_brands {
                    fail(
                        "R-UA-CH",
                        &["clientHints.brands", "engine"],
                        "Client Hints brands do not exactly match the ordered engine-target list"
                            .into(),
                    );
                }
                if hints.full_version_list != target.client_hint_full_version_list {
                    fail(
                        "R-UA-CH",
                        &["clientHints.fullVersionList", "engine.fullVersion"],
                        "Client Hints full-version-list does not exactly match the ordered engine-target list"
                            .into(),
                    );
                }
            }
            if config.persona.os.arch == CpuArch::X86_64
                && (hints.architecture != "x86" || hints.bitness != "64")
            {
                fail(
                    "R-UA-CH",
                    &[
                        "clientHints.architecture",
                        "clientHints.bitness",
                        "persona.os.arch",
                    ],
                    "Client Hints architecture/bitness contradict x86_64".into(),
                );
            }
            if config.persona.os.name == OsName::Windows
                && config.persona.os.arch == CpuArch::X86_64
                && matches!(
                    config.persona.device.class,
                    DeviceClass::Desktop | DeviceClass::Laptop
                )
                && !hints.model.is_empty()
            {
                fail(
                    "R-UA-CH",
                    &["clientHints.model", "persona.os", "persona.device.class"],
                    "Windows x86_64 desktop/laptop Client Hints model must be empty".into(),
                );
            }
        }
        (EngineFamily::Firefox, None) => {}
    }

    let gpu_profiles = dataset.gpu_profiles_by_os.get(os);
    let gpu_profile = gpu_profiles.and_then(|profiles| {
        profiles.iter().find(|profile| {
            profile.webgl_vendor == config.gpu.webgl_vendor
                && profile.webgl_renderer == config.gpu.webgl_renderer
        })
    });
    if gpu_profile.is_none() {
        fail(
            "R-PLATFORM-GPU",
            &["persona.os.name", "gpu.webglVendor", "gpu.webglRenderer"],
            "WebGL GPU profile is not valid for the persona OS".into(),
        );
    }
    if gpu_profile.is_some_and(|profile| {
        !profile
            .allowed_device_classes
            .contains(&config.persona.device.class)
    }) {
        fail(
            "R-PLATFORM-GPU",
            &[
                "persona.os.name",
                "persona.device.class",
                "gpu.webglVendor",
                "gpu.webglRenderer",
            ],
            "WebGL GPU profile is not valid for the persona OS and device class".into(),
        );
    }
    if let Some(profile) = gpu_profile
        && config.gpu.webgl_extensions != profile.webgl_extensions
    {
        fail(
            "R-WEBGL-WEBGPU",
            &["gpu.webglRenderer", "gpu.webglExtensions"],
            "WebGL extensions do not exactly match the selected GPU profile".into(),
        );
    }
    match (gpu_profile, config.gpu.webgpu_adapter.as_ref()) {
        (Some(profile), Some(adapter))
            if adapter != &profile.webgpu_adapter || adapter.family != profile.family =>
        {
            fail(
                "R-WEBGL-WEBGPU",
                &["gpu.webglRenderer", "gpu.webgpuAdapter"],
                "WebGPU adapter does not exactly match the selected WebGL GPU profile".into(),
            );
        }
        (Some(_), None) => fail(
            "R-WEBGL-WEBGPU",
            &["gpu.webglRenderer", "gpu.webgpuAdapter"],
            "seed Chrome target requires a WebGPU adapter".into(),
        ),
        _ => {}
    }

    let class = config.persona.device.class.as_str();
    let screen_known = dataset
        .screen_tuples_by_class
        .get(class)
        .is_some_and(|tuples| {
            tuples.iter().any(|tuple| {
                tuple.width == config.screen.width
                    && tuple.height == config.screen.height
                    && tuple.dpr == config.screen.device_pixel_ratio
            })
        });
    if !screen_known
        || config.screen.color_depth != 24
        || config.screen.avail_width != config.screen.width
        || config.screen.avail_height != config.screen.height.saturating_sub(40)
    {
        fail(
            "R-SCREEN-REAL",
            &["screen", "persona.device.class"],
            "screen tuple, color depth, and available dimensions must exactly match a seed mode"
                .into(),
        );
    }

    let hardware_known = dataset
        .hardware_pairs_by_class
        .get(class)
        .is_some_and(|pairs| {
            pairs.iter().any(|pair| {
                pair.hardware_concurrency == config.navigator.hardware_concurrency
                    && (pair.device_memory - config.navigator.device_memory).abs() < f64::EPSILON
            })
        });
    if !hardware_known {
        fail(
            "R-HW-PAIR",
            &[
                "persona.device.class",
                "navigator.hardwareConcurrency",
                "navigator.deviceMemory",
            ],
            "hardware concurrency/memory pair is not in the joint seed table".into(),
        );
    }

    if let Some(font_reference) = dataset.fonts_by_os.get(os) {
        let present = config.fonts.set.iter().cloned().collect::<BTreeSet<_>>();
        let missing = font_reference
            .core
            .iter()
            .filter(|font| !present.contains(*font))
            .cloned()
            .collect::<Vec<_>>();
        let allowed = font_reference
            .superset
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        let foreign = present
            .iter()
            .filter(|font| !allowed.contains(*font))
            .cloned()
            .collect::<Vec<_>>();
        if !missing.is_empty() || !foreign.is_empty() {
            fail(
                "R-FONT-OS",
                &["fonts.set", "persona.os.name"],
                format!(
                    "font policy has missing core fonts {missing:?} or foreign fonts {foreign:?}"
                ),
            );
        }
    } else {
        fail(
            "R-FONT-OS",
            &["persona.os.name"],
            "persona OS has no font reference".into(),
        );
    }

    let media_known =
        dataset
            .media_profiles_by_os
            .get(os)
            .and_then(|profiles| {
                profiles
                    .iter()
                    .find(|profile| profile.id == config.media.profile_id)
            })
            .is_some_and(|profile| {
                profile.devices.len() == config.media.devices.len()
                    && profile.devices.iter().zip(&config.media.devices).all(
                        |(expected, actual)| {
                            expected.kind == actual.kind
                                && expected.label == actual.label
                                && !actual.device_id.is_empty()
                                && !actual.group_id.is_empty()
                        },
                    )
                    && profile.speech_voices == config.media.speech_voices
            });
    if !media_known {
        fail(
            "R-MEDIA-OS",
            &["media", "persona.os.name"],
            "media devices or speech voices do not match an OS seed profile".into(),
        );
    }
    let unique_device_ids = config
        .media
        .devices
        .iter()
        .map(|device| &device.device_id)
        .collect::<BTreeSet<_>>();
    if unique_device_ids.len() != config.media.devices.len() {
        fail(
            "R-MEDIA-OS",
            &["media.devices"],
            "media device IDs must be non-repeating".into(),
        );
    }

    let region = dataset.timezone_to_region.get(&config.locale.timezone);
    let locale_reference = region.and_then(|code| dataset.locale_by_region.get(code));
    if locale_reference.is_none() {
        fail(
            "R-TZ-GEO",
            &["locale.timezone"],
            "timezone is unknown to the loaded dataset".into(),
        );
    }
    if let Some(reference) = locale_reference {
        let language = config.navigator.languages.first();
        let accept_head = config
            .locale
            .accept_language
            .split(',')
            .next()
            .map(str::trim);
        if language.map(String::as_str) != Some(reference.language_head.as_str())
            || accept_head != Some(reference.language_head.as_str())
            || config.locale.intl_locale != reference.language_head
        {
            fail(
                "R-LANG",
                &[
                    "navigator.languages",
                    "locale.acceptLanguage",
                    "locale.intlLocale",
                    "locale.timezone",
                ],
                "language, Accept-Language, Intl locale, and timezone region disagree".into(),
            );
        }
    }

    let expected_precision = dataset
        .performance_by_family
        .get(config.engine.family.as_str())
        .map(|reference| reference.timer_precision_micros);
    if expected_precision != Some(config.performance.timer_precision_micros) {
        fail(
            "R-PERF-PRECISION",
            &["performance.timerPrecisionMicros", "engine.family"],
            "timer precision does not match the engine-family seed policy".into(),
        );
    }

    if config.noise.canvas.amplitude != NoiseAmplitude::HardwareNatural
        || config.noise.webgl.amplitude != NoiseAmplitude::HardwareNatural
        || config.noise.audio.amplitude != NoiseAmplitude::HardwareNatural
    {
        fail(
            "R-NOISE-BOUNDS",
            &["noise"],
            "noise amplitude must remain within hw-natural bounds".into(),
        );
    }
    if !is_canonical_f64(config.rarity.score) || !(0.0..=1.0).contains(&config.rarity.score) {
        fail(
            "R-RARITY-RANGE",
            &["rarity.score"],
            "rarity score must be a finite number in [0,1]".into(),
        );
    }
    let expected_verdict = if config.rarity.score >= 0.7 {
        RarityVerdict::BlendsIn
    } else if config.rarity.score >= 0.5 {
        RarityVerdict::Borderline
    } else {
        RarityVerdict::TooRare
    };
    if config.rarity.verdict != expected_verdict {
        fail(
            "R-RARITY-RANGE",
            &["rarity.score", "rarity.verdict"],
            "rarity verdict does not match its score".into(),
        );
    }

    if config.provenance.dataset_version != dataset.version
        || config.provenance.dataset_sha256 != dataset.sha256
        || config.provenance.rules_version != dataset.rules_version
        || config.provenance.engine_version != config.engine.full_version
        || config.provenance.generator_version != GENERATOR_VERSION
    {
        fail(
            "R-PROVENANCE",
            &["provenance"],
            "provenance versions do not identify the exact generation inputs".into(),
        );
    }

    ValidationReport {
        valid: issues.is_empty(),
        rules_version: dataset.rules_version.clone(),
        dataset_version: dataset.version.clone(),
        issues,
    }
}

pub fn is_uuid(value: &str) -> bool {
    if value.len() != 36 {
        return false;
    }
    value.bytes().enumerate().all(|(index, byte)| {
        if matches!(index, 8 | 13 | 18 | 23) {
            byte == b'-'
        } else {
            byte.is_ascii_hexdigit()
        }
    })
}
