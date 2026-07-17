use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Public generation request

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GenerateRequest {
    /// Standard base64 encoding of exactly 32 bytes.
    pub seed: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile_id: Option<String>,
    pub engine: EngineRequest,
    pub persona: PersonaParams,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EngineRequest {
    pub brand: BrowserBrand,
    /// Required so deterministic replay preserves the caller's target
    /// constraint when a dataset contains more than one live major.
    pub major_version: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PersonaParams {
    pub os: OsConfig,
    pub device: DeviceConfig,
    /// ISO 3166-1 alpha-2 region used to derive timezone and language.
    pub region: String,
}

// ---------------------------------------------------------------------------
// Normative config body (everything covered by the signature)

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConfigBody {
    pub schema_version: String,
    pub profile_id: String,
    pub seed: String,
    pub engine: EngineConfig,
    pub persona: PersonaConfig,
    pub navigator: NavigatorConfig,
    /// Firefox-family configs encode this as null; Chromium requires an object.
    pub client_hints: Option<ClientHintsConfig>,
    pub screen: ScreenConfig,
    pub gpu: GpuConfig,
    pub fonts: FontConfig,
    pub media: MediaConfig,
    pub locale: LocaleConfig,
    pub performance: PerformanceConfig,
    pub noise: NoiseConfig,
    pub network: NetworkConfig,
    pub rarity: RarityConfig,
    pub provenance: Provenance,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EngineConfig {
    pub family: EngineFamily,
    pub brand: BrowserBrand,
    pub major_version: u32,
    pub full_version: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EngineFamily {
    Chromium,
    Firefox,
}

impl EngineFamily {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Chromium => "chromium",
            Self::Firefox => "firefox",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BrowserBrand {
    Chrome,
    Edge,
    Brave,
    Opera,
    Firefox,
}

impl BrowserBrand {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Chrome => "Chrome",
            Self::Edge => "Edge",
            Self::Brave => "Brave",
            Self::Opera => "Opera",
            Self::Firefox => "Firefox",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PersonaConfig {
    pub os: OsConfig,
    pub device: DeviceConfig,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OsConfig {
    pub name: OsName,
    pub version: String,
    pub arch: CpuArch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OsName {
    Windows,
    #[serde(rename = "macOS")]
    MacOs,
    Linux,
    #[serde(rename = "ChromeOS")]
    ChromeOs,
    Android,
    #[serde(rename = "iOS")]
    Ios,
}

impl OsName {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Windows => "Windows",
            Self::MacOs => "macOS",
            Self::Linux => "Linux",
            Self::ChromeOs => "ChromeOS",
            Self::Android => "Android",
            Self::Ios => "iOS",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CpuArch {
    #[serde(rename = "x86_64")]
    X86_64,
    #[serde(rename = "arm64")]
    Arm64,
    #[serde(rename = "x86")]
    X86,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeviceConfig {
    pub class: DeviceClass,
    #[serde(default)]
    pub model: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DeviceClass {
    Desktop,
    Laptop,
    Tablet,
    Phone,
}

impl DeviceClass {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Desktop => "desktop",
            Self::Laptop => "laptop",
            Self::Tablet => "tablet",
            Self::Phone => "phone",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NavigatorConfig {
    pub user_agent: String,
    pub platform: String,
    pub languages: Vec<String>,
    pub hardware_concurrency: u32,
    pub device_memory: f64,
    pub vendor: String,
    #[serde(default)]
    pub oscpu: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClientHintsConfig {
    pub brands: Vec<BrandVersion>,
    pub full_version_list: Vec<BrandVersion>,
    pub platform: String,
    pub platform_version: String,
    pub architecture: String,
    pub bitness: String,
    pub model: String,
    pub mobile: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrandVersion {
    pub brand: String,
    pub version: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ScreenConfig {
    pub width: u32,
    pub height: u32,
    pub avail_width: u32,
    pub avail_height: u32,
    pub color_depth: u32,
    pub device_pixel_ratio: f64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GpuConfig {
    pub webgl_vendor: String,
    pub webgl_renderer: String,
    pub webgl_extensions: Vec<String>,
    pub webgpu_adapter: Option<WebGpuAdapter>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WebGpuAdapter {
    pub family: String,
    pub vendor: String,
    pub architecture: String,
    pub device: String,
    pub description: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FontConfig {
    pub set: Vec<String>,
    pub policy: FontPolicy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FontPolicy {
    #[serde(rename = "os-superset-restricted")]
    OsSupersetRestricted,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MediaConfig {
    pub profile_id: String,
    pub devices: Vec<MediaDevice>,
    pub speech_voices: Vec<SpeechVoice>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MediaDevice {
    pub kind: String,
    pub label: String,
    pub device_id: String,
    pub group_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SpeechVoice {
    pub name: String,
    pub lang: String,
    pub local_service: bool,
    pub default: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LocaleConfig {
    pub timezone: String,
    pub accept_language: String,
    pub intl_locale: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PerformanceConfig {
    pub timer_precision_micros: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NoiseConfig {
    pub canvas: NoiseSpec,
    pub webgl: NoiseSpec,
    pub audio: NoiseSpec,
    pub client_rects: ClientRectsNoise,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NoiseSpec {
    pub mode: NoiseMode,
    pub amplitude: NoiseAmplitude,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NoiseMode {
    Off,
    Perturb,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NoiseAmplitude {
    #[serde(rename = "hw-natural")]
    HardwareNatural,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientRectsNoise {
    pub mode: ClientRectsMode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ClientRectsMode {
    Off,
    Subpixel,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NetworkConfig {
    pub quic_policy: QuicPolicy,
    pub webrtc_policy: WebRtcPolicy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum QuicPolicy {
    #[serde(rename = "match-brand")]
    MatchBrand,
    #[serde(rename = "disable-coherently")]
    DisableCoherently,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WebRtcPolicy {
    #[serde(rename = "proxy-only")]
    ProxyOnly,
    #[serde(rename = "disabled")]
    Disabled,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RarityConfig {
    pub score: f64,
    pub verdict: RarityVerdict,
    pub reasons: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RarityVerdict {
    #[serde(rename = "blends-in")]
    BlendsIn,
    #[serde(rename = "borderline")]
    Borderline,
    #[serde(rename = "too-rare")]
    TooRare,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Provenance {
    pub dataset_version: String,
    pub dataset_sha256: String,
    pub engine_version: String,
    pub rules_version: String,
    pub generator_version: String,
}

// ---------------------------------------------------------------------------
// Signed envelope

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignatureEnvelope {
    pub algorithm: SignatureAlgorithm,
    pub canonicalization: Canonicalization,
    pub domain: String,
    #[serde(rename = "keyId")]
    pub key_id: String,
    pub value: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignatureAlgorithm {
    Ed25519,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Canonicalization {
    #[serde(rename = "RFC8785")]
    Rfc8785,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SignedProfileConfig {
    pub body: ConfigBody,
    pub signature: SignatureEnvelope,
}

// ---------------------------------------------------------------------------
// Validation contract

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ValidationIssue {
    pub rule_id: String,
    pub fields: Vec<String>,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ValidationReport {
    pub valid: bool,
    pub rules_version: String,
    pub dataset_version: String,
    pub issues: Vec<ValidationIssue>,
}

// ---------------------------------------------------------------------------
// Dataset records (public because callers may inspect the transparent seed data)

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EngineTarget {
    pub family: String,
    pub brand: String,
    pub major_version: u32,
    pub full_version: String,
    pub weight: u32,
    pub platform_versions: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GpuProfile {
    pub family: String,
    pub webgl_vendor: String,
    pub webgl_renderer: String,
    pub webgpu_adapter: WebGpuAdapter,
    pub weight: u32,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScreenTuple {
    pub width: u32,
    pub height: u32,
    pub dpr: f64,
}

impl ScreenTuple {
    pub fn weight_key(&self) -> String {
        format!(
            "{}x{}@{}",
            self.width,
            self.height,
            format_number_for_key(self.dpr)
        )
    }
}

fn format_number_for_key(value: f64) -> String {
    if value.fract() == 0.0 {
        format!("{value:.0}")
    } else {
        value.to_string()
    }
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HardwarePair {
    pub hardware_concurrency: u32,
    pub device_memory: f64,
    pub weight: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FontReference {
    pub core: Vec<String>,
    pub superset: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FontProfile {
    pub id: String,
    pub set: Vec<String>,
    pub weight: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MediaProfile {
    pub id: String,
    pub devices: Vec<MediaDeviceTemplate>,
    pub speech_voices: Vec<SpeechVoice>,
    pub weight: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MediaDeviceTemplate {
    pub kind: String,
    pub label: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocaleReference {
    pub timezones: Vec<String>,
    #[serde(rename = "languageHead")]
    pub language_head: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PerformanceReference {
    pub timer_precision_micros: u32,
}
