use std::collections::BTreeMap;

use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::error::{FingerprintError, Result};
use crate::model::{
    EngineTarget, FontProfile, FontReference, GpuProfile, HardwarePair, LocaleReference,
    MediaProfile, PerformanceReference, ScreenTuple,
};
use crate::schema_contract::is_canonical_f64;
use crate::schema_contract::{is_full_version, is_media_device_kind};
use crate::signature::parse_unique_json;

/// Parsed, versioned seed dataset shared with the verification lab.
///
/// A dataset is immutable after parsing so that [`Dataset::sha256`] always
/// describes the exact bytes from which every generation table was decoded.
/// Callers can inspect every table through read-only accessors, but cannot
/// replace validated values while retaining stale provenance.
///
/// ```compile_fail
/// # use proteus_fingerprint::Dataset;
/// # fn cannot_mutate(dataset: &mut Dataset) {
/// dataset.engine_targets.clear();
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct Dataset {
    pub(crate) version: String,
    pub(crate) sha256: String,
    pub(crate) rules_version: String,
    pub(crate) platform_by_os: BTreeMap<String, Vec<String>>,
    pub(crate) gpu_vendor_families_by_os: BTreeMap<String, Vec<String>>,
    pub(crate) fonts_by_os: BTreeMap<String, FontReference>,
    pub(crate) screen_tuples_by_class: BTreeMap<String, Vec<ScreenTuple>>,
    pub(crate) locale_by_region: BTreeMap<String, LocaleReference>,
    pub(crate) timezone_to_region: BTreeMap<String, String>,
    pub(crate) live_version_window: BTreeMap<String, VersionWindow>,
    pub(crate) vendor_by_family: BTreeMap<String, String>,
    pub(crate) engine_targets: Vec<EngineTarget>,
    pub(crate) gpu_profiles_by_os: BTreeMap<String, Vec<GpuProfile>>,
    pub(crate) screen_weights_by_class: BTreeMap<String, BTreeMap<String, u32>>,
    pub(crate) hardware_pairs_by_class: BTreeMap<String, Vec<HardwarePair>>,
    pub(crate) font_profiles_by_os: BTreeMap<String, Vec<FontProfile>>,
    pub(crate) media_profiles_by_os: BTreeMap<String, Vec<MediaProfile>>,
    pub(crate) performance_by_family: BTreeMap<String, PerformanceReference>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VersionWindow {
    pub min: u32,
    pub max: u32,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct RawDataset {
    #[serde(rename = "_comment")]
    _comment: Option<Value>,
    #[serde(rename = "_version")]
    version: String,
    #[serde(rename = "_rulesVersion")]
    rules_version: String,
    platform_by_os: BTreeMap<String, Value>,
    gpu_vendor_families_by_os: BTreeMap<String, Value>,
    #[serde(rename = "gpuVendorStringMarkers")]
    _gpu_vendor_string_markers: Value,
    fonts_by_os: BTreeMap<String, Value>,
    screen_tuples_by_class: BTreeMap<String, Value>,
    #[serde(rename = "hardwareByClass")]
    _hardware_by_class: Value,
    locale_by_region: BTreeMap<String, Value>,
    timezone_to_region: BTreeMap<String, Value>,
    #[serde(rename = "browserFamily")]
    _browser_family: Value,
    live_version_window: BTreeMap<String, Value>,
    vendor_by_family: BTreeMap<String, Value>,
    engine_targets: Vec<EngineTarget>,
    gpu_profiles_by_os: BTreeMap<String, Value>,
    screen_weights_by_class: BTreeMap<String, Value>,
    hardware_pairs_by_class: BTreeMap<String, Value>,
    font_profiles_by_os: BTreeMap<String, Value>,
    media_profiles_by_os: BTreeMap<String, Value>,
    performance_by_family: BTreeMap<String, Value>,
}

impl Dataset {
    /// Parse a dataset JSON document, rejecting missing or malformed generation
    /// tables. Comment keys beginning with `_` are ignored deliberately.
    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        let raw: RawDataset = serde_json::from_value(parse_unique_json(bytes)?)?;
        if raw.version.trim().is_empty() || raw.rules_version.trim().is_empty() {
            return Err(FingerprintError::InvalidDataset(
                "dataset and rules versions must be non-empty".into(),
            ));
        }
        if raw.rules_version != crate::RULES_VERSION {
            return Err(FingerprintError::InvalidDataset(format!(
                "dataset rules version {} does not match Rust catalog {}",
                raw.rules_version,
                crate::RULES_VERSION
            )));
        }

        let dataset = Self {
            version: raw.version,
            sha256: hex(Sha256::digest(bytes)),
            rules_version: raw.rules_version,
            platform_by_os: decode_map("platformByOs", raw.platform_by_os)?,
            gpu_vendor_families_by_os: decode_map(
                "gpuVendorFamiliesByOs",
                raw.gpu_vendor_families_by_os,
            )?,
            fonts_by_os: decode_map("fontsByOs", raw.fonts_by_os)?,
            screen_tuples_by_class: decode_map("screenTuplesByClass", raw.screen_tuples_by_class)?,
            locale_by_region: decode_map("localeByRegion", raw.locale_by_region)?,
            timezone_to_region: decode_map("timezoneToRegion", raw.timezone_to_region)?,
            live_version_window: decode_map("liveVersionWindow", raw.live_version_window)?,
            vendor_by_family: decode_map("vendorByFamily", raw.vendor_by_family)?,
            engine_targets: raw.engine_targets,
            gpu_profiles_by_os: decode_map("gpuProfilesByOs", raw.gpu_profiles_by_os)?,
            screen_weights_by_class: decode_map(
                "screenWeightsByClass",
                raw.screen_weights_by_class,
            )?,
            hardware_pairs_by_class: decode_map(
                "hardwarePairsByClass",
                raw.hardware_pairs_by_class,
            )?,
            font_profiles_by_os: decode_map("fontProfilesByOs", raw.font_profiles_by_os)?,
            media_profiles_by_os: decode_map("mediaProfilesByOs", raw.media_profiles_by_os)?,
            performance_by_family: decode_map("performanceByFamily", raw.performance_by_family)?,
        };
        dataset.sanity_check()?;
        Ok(dataset)
    }

    /// Dataset version recorded in generated profile provenance.
    pub fn version(&self) -> &str {
        &self.version
    }

    /// Lowercase SHA-256 of the exact JSON bytes parsed by [`Dataset::from_json`].
    pub fn sha256(&self) -> &str {
        &self.sha256
    }

    /// Semantic rule catalog version required by this dataset.
    pub fn rules_version(&self) -> &str {
        &self.rules_version
    }

    pub fn platform_by_os(&self) -> &BTreeMap<String, Vec<String>> {
        &self.platform_by_os
    }

    pub fn gpu_vendor_families_by_os(&self) -> &BTreeMap<String, Vec<String>> {
        &self.gpu_vendor_families_by_os
    }

    pub fn fonts_by_os(&self) -> &BTreeMap<String, FontReference> {
        &self.fonts_by_os
    }

    pub fn screen_tuples_by_class(&self) -> &BTreeMap<String, Vec<ScreenTuple>> {
        &self.screen_tuples_by_class
    }

    pub fn locale_by_region(&self) -> &BTreeMap<String, LocaleReference> {
        &self.locale_by_region
    }

    pub fn timezone_to_region(&self) -> &BTreeMap<String, String> {
        &self.timezone_to_region
    }

    pub fn live_version_window(&self) -> &BTreeMap<String, VersionWindow> {
        &self.live_version_window
    }

    pub fn vendor_by_family(&self) -> &BTreeMap<String, String> {
        &self.vendor_by_family
    }

    pub fn engine_targets(&self) -> &[EngineTarget] {
        &self.engine_targets
    }

    pub fn gpu_profiles_by_os(&self) -> &BTreeMap<String, Vec<GpuProfile>> {
        &self.gpu_profiles_by_os
    }

    pub fn screen_weights_by_class(&self) -> &BTreeMap<String, BTreeMap<String, u32>> {
        &self.screen_weights_by_class
    }

    pub fn hardware_pairs_by_class(&self) -> &BTreeMap<String, Vec<HardwarePair>> {
        &self.hardware_pairs_by_class
    }

    pub fn font_profiles_by_os(&self) -> &BTreeMap<String, Vec<FontProfile>> {
        &self.font_profiles_by_os
    }

    pub fn media_profiles_by_os(&self) -> &BTreeMap<String, Vec<MediaProfile>> {
        &self.media_profiles_by_os
    }

    pub fn performance_by_family(&self) -> &BTreeMap<String, PerformanceReference> {
        &self.performance_by_family
    }

    fn sanity_check(&self) -> Result<()> {
        if self.engine_targets.is_empty() {
            return Err(FingerprintError::InvalidDataset(
                "engineTargets must not be empty".into(),
            ));
        }
        for target in &self.engine_targets {
            if target.weight == 0 {
                return Err(FingerprintError::InvalidDataset(format!(
                    "engine target {} {} has zero weight",
                    target.brand, target.full_version
                )));
            }
            if target.major_version == 0
                || !is_full_version(&target.full_version)
                || target
                    .full_version
                    .split('.')
                    .next()
                    .and_then(|major| major.parse::<u32>().ok())
                    != Some(target.major_version)
            {
                return Err(FingerprintError::InvalidDataset(format!(
                    "engine target {} has a schema-invalid major/full version pair {}/{}",
                    target.brand, target.major_version, target.full_version
                )));
            }
        }
        for (os, profiles) in &self.gpu_profiles_by_os {
            if profiles.is_empty() || profiles.iter().any(|candidate| candidate.weight == 0) {
                return Err(FingerprintError::InvalidDataset(format!(
                    "GPU profiles for {os} must be non-empty with positive weights"
                )));
            }
        }
        for (class, tuples) in &self.screen_tuples_by_class {
            if tuples.is_empty() {
                return Err(FingerprintError::InvalidDataset(format!(
                    "screen tuples for {class} must not be empty"
                )));
            }
            let weights = self.screen_weights_by_class.get(class).ok_or_else(|| {
                FingerprintError::InvalidDataset(format!(
                    "screen tuples for {class} have no weight table"
                ))
            })?;
            for tuple in tuples {
                if tuple.width == 0
                    || tuple.height <= 40
                    || !is_canonical_f64(tuple.dpr)
                    || tuple.dpr < 0.5
                    || tuple.dpr > 16.0
                {
                    return Err(FingerprintError::InvalidDataset(format!(
                        "screen tuple {}x{}@{} for {class} violates Profile Config numeric bounds",
                        tuple.width, tuple.height, tuple.dpr
                    )));
                }
                if weights
                    .get(&tuple.weight_key())
                    .is_none_or(|weight| *weight == 0)
                {
                    return Err(FingerprintError::InvalidDataset(format!(
                        "screen tuple {} for {class} needs a positive exact weight",
                        tuple.weight_key()
                    )));
                }
            }
            if weights.values().any(|weight| *weight == 0) {
                return Err(FingerprintError::InvalidDataset(format!(
                    "screen weights for {class} must be positive"
                )));
            }
        }
        for (class, pairs) in &self.hardware_pairs_by_class {
            if pairs.is_empty()
                || pairs.iter().any(|candidate| {
                    candidate.weight == 0
                        || candidate.hardware_concurrency == 0
                        || !is_canonical_f64(candidate.device_memory)
                        || !(0.25..=1024.0).contains(&candidate.device_memory)
                })
            {
                return Err(FingerprintError::InvalidDataset(format!(
                    "hardware pairs for {class} must be non-empty, finite, and satisfy Profile Config minima"
                )));
            }
        }
        for (os, profiles) in &self.font_profiles_by_os {
            if profiles.is_empty()
                || profiles
                    .iter()
                    .any(|candidate| candidate.weight == 0 || candidate.set.is_empty())
            {
                return Err(FingerprintError::InvalidDataset(format!(
                    "font profiles for {os} must be non-empty with positive weights and font sets"
                )));
            }
        }
        for (os, profiles) in &self.media_profiles_by_os {
            if profiles.is_empty()
                || profiles.iter().any(|candidate| {
                    candidate.weight == 0
                        || candidate.devices.is_empty()
                        || candidate.speech_voices.is_empty()
                        || candidate
                            .devices
                            .iter()
                            .any(|device| !is_media_device_kind(&device.kind))
                })
            {
                return Err(FingerprintError::InvalidDataset(format!(
                    "media profiles for {os} must have positive weights, non-empty devices/voices, and schema-valid device kinds"
                )));
            }
        }
        for (family, performance) in &self.performance_by_family {
            if performance.timer_precision_micros == 0 {
                return Err(FingerprintError::InvalidDataset(format!(
                    "performance timer precision for {family} must be at least one microsecond"
                )));
            }
        }
        for (region, locale) in &self.locale_by_region {
            if locale.timezones.is_empty() || locale.language_head.trim().is_empty() {
                return Err(FingerprintError::InvalidDataset(format!(
                    "locale {region} needs a timezone and non-empty language head"
                )));
            }
            for timezone in &locale.timezones {
                if self.timezone_to_region.get(timezone) != Some(region) {
                    return Err(FingerprintError::InvalidDataset(format!(
                        "timezone {timezone} does not reverse-map to locale region {region}"
                    )));
                }
            }
        }
        for (timezone, region) in &self.timezone_to_region {
            if !self
                .locale_by_region
                .get(region)
                .is_some_and(|locale| locale.timezones.contains(timezone))
            {
                return Err(FingerprintError::InvalidDataset(format!(
                    "timezone mapping {timezone}->{region} has no matching locale entry"
                )));
            }
        }
        Ok(())
    }
}

fn hex(bytes: impl AsRef<[u8]>) -> String {
    let mut output = String::with_capacity(bytes.as_ref().len() * 2);
    for byte in bytes.as_ref() {
        use std::fmt::Write as _;
        write!(&mut output, "{byte:02x}").expect("writing to String cannot fail");
    }
    output
}

fn decode_map<T: DeserializeOwned>(
    field: &str,
    raw: BTreeMap<String, Value>,
) -> Result<BTreeMap<String, T>> {
    raw.into_iter()
        .filter(|(key, _)| !key.starts_with('_'))
        .map(|(key, value)| {
            serde_json::from_value(value)
                .map(|decoded| (key.clone(), decoded))
                .map_err(|error| {
                    FingerprintError::InvalidDataset(format!("{field}.{key}: {error}"))
                })
        })
        .collect()
}
