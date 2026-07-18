use base64::{Engine as _, engine::general_purpose::STANDARD};

use crate::GENERATOR_VERSION;
use crate::dataset::Dataset;
use crate::error::{FingerprintError, Result};
use crate::model::{
    BrowserBrand, ClientHintsConfig, ClientRectsMode, ClientRectsNoise, ConfigBody, DeviceClass,
    EngineConfig, EngineFamily, EngineRequest, FontConfig, FontPolicy, GenerateRequest, GpuConfig,
    LocaleConfig, MediaConfig, MediaDevice, NavigatorConfig, NetworkConfig, NoiseAmplitude,
    NoiseConfig, NoiseMode, NoiseSpec, OsName, PerformanceConfig, PersonaConfig, PersonaParams,
    Provenance, QuicPolicy, RarityConfig, RarityVerdict, ScreenConfig, WebRtcPolicy,
};
use crate::sampler::DeterministicSampler;
use crate::validate::validate;

pub const PROFILE_SCHEMA_VERSION: &str = "1.0.0";

/// Successful generation output. Signing is deliberately a separate Manager
/// boundary; this structure contains only the deterministic unsigned body.
#[derive(Debug, Clone, PartialEq)]
pub struct GeneratedProfile {
    pub body: ConfigBody,
    pub blend_in: f64,
    pub rarity_reasons: Vec<String>,
}

pub fn generate(request: &GenerateRequest, dataset: &Dataset) -> Result<GeneratedProfile> {
    let seed = decode_seed(&request.seed)?;
    validate_request(request)?;
    let sampler = DeterministicSampler::new(seed);

    if request.engine.brand != BrowserBrand::Chrome {
        return Err(FingerprintError::NoCandidate(
            "M1A currently supports the Chromium/Chrome target only".into(),
        ));
    }
    let targets = dataset
        .engine_targets
        .iter()
        .filter(|target| {
            target.family == "chromium"
                && target.brand == request.engine.brand.as_str()
                && target.major_version == request.engine.major_version
        })
        .collect::<Vec<_>>();
    let target_index = sampler.choose_weighted(
        "engine-target",
        &targets
            .iter()
            .map(|target| target.weight)
            .collect::<Vec<_>>(),
    )?;
    let target = targets[target_index];

    let os_name = request.persona.os.name.as_str();
    if request.persona.os.name != OsName::Windows {
        return Err(FingerprintError::NoCandidate(
            "the M1A seed dataset currently supports Windows generation only".into(),
        ));
    }
    if !matches!(
        request.persona.device.class,
        DeviceClass::Desktop | DeviceClass::Laptop
    ) {
        return Err(FingerprintError::NoCandidate(
            "the M1A seed dataset supports desktop and laptop personas only".into(),
        ));
    }

    let platform = dataset
        .platform_by_os
        .get(os_name)
        .and_then(|values| values.first())
        .cloned()
        .ok_or_else(|| {
            FingerprintError::NoCandidate(format!("no navigator platform for {os_name}"))
        })?;

    let class = request.persona.device.class.as_str();
    let all_gpu_candidates = required_candidates(&dataset.gpu_profiles_by_os, os_name, "GPU")?;
    let gpu_candidates = all_gpu_candidates
        .iter()
        .filter(|candidate| {
            candidate
                .allowed_device_classes
                .contains(&request.persona.device.class)
        })
        .collect::<Vec<_>>();
    let gpu_index = sampler.choose_weighted(
        "gpu",
        &gpu_candidates
            .iter()
            .map(|candidate| candidate.weight)
            .collect::<Vec<_>>(),
    )?;
    let gpu = gpu_candidates[gpu_index];

    let screen_candidates = required_candidates(&dataset.screen_tuples_by_class, class, "screen")?;
    let screen_weights = dataset
        .screen_weights_by_class
        .get(class)
        .ok_or_else(|| FingerprintError::NoCandidate(format!("no screen weights for {class}")))?;
    let weights = screen_candidates
        .iter()
        .map(|candidate| {
            screen_weights
                .get(&candidate.weight_key())
                .copied()
                .unwrap_or(1)
        })
        .collect::<Vec<_>>();
    let screen_index = sampler.choose_weighted("screen", &weights)?;
    let screen = &screen_candidates[screen_index];

    let hardware_candidates =
        required_candidates(&dataset.hardware_pairs_by_class, class, "hardware")?;
    let hardware_index = sampler.choose_weighted(
        "hardware",
        &hardware_candidates
            .iter()
            .map(|candidate| candidate.weight)
            .collect::<Vec<_>>(),
    )?;
    let hardware = &hardware_candidates[hardware_index];

    let font_candidates =
        required_candidates(&dataset.font_profiles_by_os, os_name, "font profile")?;
    let font_index = sampler.choose_weighted(
        "font-profile",
        &font_candidates
            .iter()
            .map(|candidate| candidate.weight)
            .collect::<Vec<_>>(),
    )?;
    let font_profile = &font_candidates[font_index];

    let media_candidates =
        required_candidates(&dataset.media_profiles_by_os, os_name, "media profile")?;
    let media_index = sampler.choose_weighted(
        "media-profile",
        &media_candidates
            .iter()
            .map(|candidate| candidate.weight)
            .collect::<Vec<_>>(),
    )?;
    let media_profile = &media_candidates[media_index];

    let region = request.persona.region.to_ascii_uppercase();
    let locale = dataset.locale_by_region.get(&region).ok_or_else(|| {
        FingerprintError::NoCandidate(format!("unsupported persona region {region}"))
    })?;
    let timezone_index = sampler.choose_weighted("timezone", &vec![1; locale.timezones.len()])?;
    let timezone = locale.timezones[timezone_index].clone();
    let language_head = locale.language_head.clone();
    let base_language = language_head
        .split('-')
        .next()
        .unwrap_or(&language_head)
        .to_string();
    let languages = if base_language == language_head {
        vec![language_head.clone()]
    } else {
        vec![language_head.clone(), base_language.clone()]
    };
    let accept_language = if base_language == language_head {
        language_head.clone()
    } else {
        format!("{language_head},{base_language};q=0.9")
    };

    let profile_id = request
        .profile_id
        .clone()
        .unwrap_or_else(|| derived_uuid(&sampler));
    let canonical_seed = STANDARD.encode(seed);
    let full_version = target.full_version.clone();
    let user_agent = windows_chrome_user_agent(target.major_version);
    let platform_version = target
        .platform_versions
        .get(os_name)
        .cloned()
        .ok_or_else(|| {
            FingerprintError::NoCandidate(format!(
                "engine target lacks a platform version for {os_name}"
            ))
        })?;

    let media_devices = media_profile
        .devices
        .iter()
        .enumerate()
        .map(|(index, template)| MediaDevice {
            kind: template.kind.clone(),
            label: template.label.clone(),
            device_id: sampler.stable_token(&format!("media/device/{index}"), 18),
            group_id: sampler
                .stable_token(&format!("media/group/{}", media_group(&template.kind)), 18),
        })
        .collect();

    let rarity = rarity_from_factors(&[
        (
            "engine target",
            target.weight,
            max_weight(&targets, |item| item.weight),
        ),
        (
            "GPU profile",
            gpu.weight,
            max_weight(&gpu_candidates, |item| item.weight),
        ),
        (
            "screen tuple",
            weights[screen_index],
            weights.iter().copied().max().unwrap_or(1),
        ),
        (
            "hardware pair",
            hardware.weight,
            max_weight(hardware_candidates, |item| item.weight),
        ),
        (
            "font profile",
            font_profile.weight,
            max_weight(font_candidates, |item| item.weight),
        ),
        (
            "media profile",
            media_profile.weight,
            max_weight(media_candidates, |item| item.weight),
        ),
    ]);

    let performance = dataset
        .performance_by_family
        .get(target.family.as_str())
        .ok_or_else(|| {
            FingerprintError::NoCandidate(format!("no performance policy for {}", target.family))
        })?;

    let body = ConfigBody {
        schema_version: PROFILE_SCHEMA_VERSION.into(),
        profile_id,
        seed: canonical_seed,
        engine: EngineConfig {
            family: EngineFamily::Chromium,
            brand: BrowserBrand::Chrome,
            major_version: target.major_version,
            full_version: full_version.clone(),
        },
        persona: PersonaConfig {
            os: request.persona.os.clone(),
            device: request.persona.device.clone(),
        },
        navigator: NavigatorConfig {
            user_agent,
            platform,
            languages,
            hardware_concurrency: hardware.hardware_concurrency,
            device_memory: hardware.device_memory,
            vendor: "Google Inc.".into(),
            oscpu: None,
        },
        client_hints: Some(ClientHintsConfig {
            brands: target.client_hint_brands.clone(),
            full_version_list: target.client_hint_full_version_list.clone(),
            platform: "Windows".into(),
            platform_version,
            architecture: "x86".into(),
            bitness: "64".into(),
            model: String::new(),
            mobile: false,
        }),
        screen: ScreenConfig {
            width: screen.width,
            height: screen.height,
            avail_width: screen.width,
            avail_height: screen.height.saturating_sub(40),
            color_depth: 24,
            device_pixel_ratio: screen.dpr,
        },
        gpu: GpuConfig {
            webgl_vendor: gpu.webgl_vendor.clone(),
            webgl_renderer: gpu.webgl_renderer.clone(),
            webgl_extensions: gpu.webgl_extensions.clone(),
            webgpu_adapter: Some(gpu.webgpu_adapter.clone()),
        },
        fonts: FontConfig {
            set: font_profile.set.clone(),
            policy: FontPolicy::OsSupersetRestricted,
        },
        media: MediaConfig {
            profile_id: media_profile.id.clone(),
            devices: media_devices,
            speech_voices: media_profile.speech_voices.clone(),
        },
        locale: LocaleConfig {
            timezone,
            accept_language,
            intl_locale: language_head,
        },
        performance: PerformanceConfig {
            timer_precision_micros: performance.timer_precision_micros,
        },
        noise: NoiseConfig {
            canvas: perturb_noise(),
            webgl: perturb_noise(),
            audio: perturb_noise(),
            client_rects: ClientRectsNoise {
                mode: ClientRectsMode::Subpixel,
            },
        },
        network: NetworkConfig {
            quic_policy: QuicPolicy::MatchBrand,
            webrtc_policy: WebRtcPolicy::ProxyOnly,
        },
        rarity: rarity.clone(),
        provenance: Provenance {
            dataset_version: dataset.version.clone(),
            dataset_sha256: dataset.sha256.clone(),
            engine_version: target.full_version.clone(),
            rules_version: dataset.rules_version.clone(),
            generator_version: GENERATOR_VERSION.into(),
        },
    };

    let report = validate(&body, dataset);
    if !report.valid {
        let summary = report
            .issues
            .iter()
            .map(|issue| format!("{}: {}", issue.rule_id, issue.reason))
            .collect::<Vec<_>>()
            .join("; ");
        return Err(FingerprintError::Validation(summary));
    }

    Ok(GeneratedProfile {
        blend_in: rarity.score,
        rarity_reasons: rarity.reasons.clone(),
        body,
    })
}

/// Recompute the transparent seed rarity heuristic for an existing config.
pub fn rescore(config: &ConfigBody, dataset: &Dataset) -> Result<RarityConfig> {
    let os = config.persona.os.name.as_str();
    let class = config.persona.device.class.as_str();
    let target_candidates = dataset
        .engine_targets
        .iter()
        .filter(|target| {
            target.family == config.engine.family.as_str()
                && target.brand == config.engine.brand.as_str()
                && target.major_version == config.engine.major_version
        })
        .collect::<Vec<_>>();
    let target = target_candidates
        .iter()
        .find(|target| target.full_version == config.engine.full_version)
        .ok_or_else(|| FingerprintError::NoCandidate("engine target is not in dataset".into()))?;
    let all_gpu_candidates = required_candidates(&dataset.gpu_profiles_by_os, os, "GPU")?;
    let gpu_candidates = all_gpu_candidates
        .iter()
        .filter(|candidate| {
            candidate
                .allowed_device_classes
                .contains(&config.persona.device.class)
        })
        .collect::<Vec<_>>();
    let gpu = gpu_candidates
        .iter()
        .find(|candidate| {
            candidate.webgl_vendor == config.gpu.webgl_vendor
                && candidate.webgl_renderer == config.gpu.webgl_renderer
                && candidate.webgl_extensions == config.gpu.webgl_extensions
                && config.gpu.webgpu_adapter.as_ref() == Some(&candidate.webgpu_adapter)
        })
        .ok_or_else(|| FingerprintError::NoCandidate("GPU profile is not in dataset".into()))?;
    let screen_weights = dataset
        .screen_weights_by_class
        .get(class)
        .ok_or_else(|| FingerprintError::NoCandidate("screen class is not in dataset".into()))?;
    let screen_key = format!(
        "{}x{}@{}",
        config.screen.width,
        config.screen.height,
        number_key(config.screen.device_pixel_ratio)
    );
    let screen_weight = *screen_weights
        .get(&screen_key)
        .ok_or_else(|| FingerprintError::NoCandidate("screen tuple is not in dataset".into()))?;
    let hardware_candidates =
        required_candidates(&dataset.hardware_pairs_by_class, class, "hardware")?;
    let hardware = hardware_candidates
        .iter()
        .find(|candidate| {
            candidate.hardware_concurrency == config.navigator.hardware_concurrency
                && (candidate.device_memory - config.navigator.device_memory).abs() < f64::EPSILON
        })
        .ok_or_else(|| FingerprintError::NoCandidate("hardware pair is not in dataset".into()))?;
    let font_candidates = required_candidates(&dataset.font_profiles_by_os, os, "font")?;
    let font = font_candidates
        .iter()
        .find(|candidate| candidate.set == config.fonts.set)
        .ok_or_else(|| FingerprintError::NoCandidate("font profile is not in dataset".into()))?;
    let media_candidates = required_candidates(&dataset.media_profiles_by_os, os, "media")?;
    let media = media_candidates
        .iter()
        .find(|candidate| candidate.id == config.media.profile_id)
        .ok_or_else(|| FingerprintError::NoCandidate("media profile is not in dataset".into()))?;

    Ok(rarity_from_factors(&[
        (
            "engine target",
            target.weight,
            max_weight(&target_candidates, |item| item.weight),
        ),
        (
            "GPU profile",
            gpu.weight,
            max_weight(&gpu_candidates, |item| item.weight),
        ),
        (
            "screen tuple",
            screen_weight,
            screen_weights.values().copied().max().unwrap_or(1),
        ),
        (
            "hardware pair",
            hardware.weight,
            max_weight(hardware_candidates, |item| item.weight),
        ),
        (
            "font profile",
            font.weight,
            max_weight(font_candidates, |item| item.weight),
        ),
        (
            "media profile",
            media.weight,
            max_weight(media_candidates, |item| item.weight),
        ),
    ]))
}

/// Rebuild a loaded config from the inputs it declares and require an exact
/// value match. Signature validity proves who authorized a document; this
/// check separately proves that derived fields were not hand-authored into an
/// otherwise coherent-looking document.
pub fn verify_reproducible(config: &ConfigBody, dataset: &Dataset) -> Result<()> {
    let region = dataset
        .timezone_to_region
        .get(&config.locale.timezone)
        .ok_or_else(|| {
            FingerprintError::DeterministicMismatch(format!(
                "locale timezone {} has no region in dataset {}",
                config.locale.timezone, dataset.version
            ))
        })?
        .clone();
    let request = GenerateRequest {
        seed: config.seed.clone(),
        profile_id: Some(config.profile_id.clone()),
        engine: EngineRequest {
            brand: config.engine.brand,
            major_version: config.engine.major_version,
        },
        persona: PersonaParams {
            os: config.persona.os.clone(),
            device: config.persona.device.clone(),
            region,
        },
    };
    let expected = generate(&request, dataset)?.body;
    if expected == *config {
        return Ok(());
    }

    let expected = serde_json::to_value(expected)?;
    let actual = serde_json::to_value(config)?;
    let path = first_difference(&expected, &actual, "$")
        .unwrap_or_else(|| "$ (serialized values differ)".into());
    Err(FingerprintError::DeterministicMismatch(path))
}

pub(crate) fn decode_seed(encoded: &str) -> Result<[u8; 32]> {
    let decoded = STANDARD.decode(encoded)?;
    decoded.try_into().map_err(|bytes: Vec<u8>| {
        FingerprintError::InvalidRequest(format!(
            "seed must decode to exactly 32 bytes, got {}",
            bytes.len()
        ))
    })
}

fn validate_request(request: &GenerateRequest) -> Result<()> {
    let region = request.persona.region.as_bytes();
    if region.len() != 2 || !region.iter().all(u8::is_ascii_alphabetic) {
        return Err(FingerprintError::InvalidRequest(
            "persona.region must be a two-letter ISO country code".into(),
        ));
    }
    if request.persona.os.version.trim().is_empty() {
        return Err(FingerprintError::InvalidRequest(
            "persona.os.version must not be empty".into(),
        ));
    }
    if request.persona.os.name == OsName::Windows
        && (request.persona.os.version != "11"
            || request.persona.os.arch != crate::model::CpuArch::X86_64)
    {
        return Err(FingerprintError::NoCandidate(
            "the M1A Windows target requires Windows 11 on x86_64".into(),
        ));
    }
    if request.persona.device.model.is_some() {
        return Err(FingerprintError::NoCandidate(
            "the M1A desktop/laptop target requires persona.device.model to be null".into(),
        ));
    }
    if let Some(profile_id) = &request.profile_id {
        if !crate::validate::is_uuid(profile_id) {
            return Err(FingerprintError::InvalidRequest(
                "profileId must be an RFC 4122 UUID".into(),
            ));
        }
    }
    Ok(())
}

fn first_difference(
    expected: &serde_json::Value,
    actual: &serde_json::Value,
    path: &str,
) -> Option<String> {
    match (expected, actual) {
        (serde_json::Value::Array(left), serde_json::Value::Array(right)) => {
            if left.len() != right.len() {
                return Some(format!("{path}.length"));
            }
            left.iter()
                .zip(right)
                .enumerate()
                .find_map(|(index, (left, right))| {
                    first_difference(left, right, &format!("{path}[{index}]"))
                })
        }
        (serde_json::Value::Object(left), serde_json::Value::Object(right)) => {
            for key in left.keys().chain(right.keys()) {
                match (left.get(key), right.get(key)) {
                    (Some(left), Some(right)) => {
                        if let Some(difference) =
                            first_difference(left, right, &format!("{path}.{key}"))
                        {
                            return Some(difference);
                        }
                    }
                    _ => return Some(format!("{path}.{key}")),
                }
            }
            None
        }
        _ if expected == actual => None,
        _ => Some(path.into()),
    }
}

fn required_candidates<'a, T>(
    map: &'a std::collections::BTreeMap<String, Vec<T>>,
    key: &str,
    label: &str,
) -> Result<&'a Vec<T>> {
    map.get(key)
        .filter(|values| !values.is_empty())
        .ok_or_else(|| FingerprintError::NoCandidate(format!("no {label} candidates for {key}")))
}

fn max_weight<T>(items: &[T], get: impl Fn(&T) -> u32) -> u32 {
    items.iter().map(get).max().unwrap_or(1)
}

fn derived_uuid(sampler: &DeterministicSampler) -> String {
    let mut bytes = sampler.derive("profile-id", 0);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0],
        bytes[1],
        bytes[2],
        bytes[3],
        bytes[4],
        bytes[5],
        bytes[6],
        bytes[7],
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15],
    )
}

pub(crate) fn windows_chrome_user_agent(major_version: u32) -> String {
    format!(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
         (KHTML, like Gecko) Chrome/{major_version}.0.0.0 Safari/537.36"
    )
}

fn media_group(kind: &str) -> &str {
    if kind.starts_with("audio") {
        "audio"
    } else {
        kind
    }
}

fn perturb_noise() -> NoiseSpec {
    NoiseSpec {
        mode: NoiseMode::Perturb,
        amplitude: NoiseAmplitude::HardwareNatural,
    }
}

fn rarity_from_factors(factors: &[(&str, u32, u32)]) -> RarityConfig {
    let ratios = factors
        .iter()
        .map(|(label, weight, max)| {
            let ratio = if *max == 0 {
                0
            } else {
                u64::from(*weight) * 1_000 / u64::from(*max)
            } as u32;
            (*label, ratio)
        })
        .collect::<Vec<_>>();
    let score_milli = if ratios.is_empty() {
        0
    } else {
        ratios
            .iter()
            .map(|(_, ratio)| u64::from(*ratio))
            .sum::<u64>()
            / u64::try_from(ratios.len()).expect("factor count fits u64")
    };
    let score = score_milli as f64 / 1_000.0;
    let reasons = ratios
        .iter()
        .filter(|(_, ratio)| *ratio < 600)
        .map(|(label, ratio)| {
            format!(
                "{label} is a lower-weight seed candidate ({}% of the modal weight)",
                ratio / 10
            )
        })
        .collect::<Vec<_>>();
    let verdict = if score >= 0.7 {
        RarityVerdict::BlendsIn
    } else if score >= 0.5 {
        RarityVerdict::Borderline
    } else {
        RarityVerdict::TooRare
    };
    RarityConfig {
        score,
        verdict,
        reasons,
    }
}

fn number_key(value: f64) -> String {
    if value.fract() == 0.0 {
        format!("{value:.0}")
    } else {
        value.to_string()
    }
}
