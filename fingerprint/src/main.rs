use std::error::Error;
use std::fs::{read, read_to_string};
use std::io::{self, Write};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use ed25519_dalek::SigningKey;
use proteus_fingerprint::{
    Dataset, GenerateRequest, TrustStore, derive_key_id, generate, sign_config, validate,
    verify_and_validate_signed_json,
};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SigningKeyDocument {
    #[serde(rename = "_warning", default)]
    _warning: Option<String>,
    private_key: String,
    #[serde(default)]
    key_id: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TrustStoreDocument {
    keys: Vec<TrustKeyDocument>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TrustKeyDocument {
    key_id: String,
    public_key: String,
}

fn main() {
    if let Err(error) = run() {
        let _ = writeln!(io::stderr().lock(), "proteus-fingerprint: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    let Some(command) = args.first().map(String::as_str) else {
        print_help();
        return Ok(());
    };
    match command {
        "generate" => cmd_generate(&args[1..]),
        "verify" => cmd_verify(&args[1..]),
        "key-id" => cmd_key_id(&args[1..]),
        "help" | "--help" | "-h" => {
            print_help();
            Ok(())
        }
        other => Err(format!("unknown command {other:?}; run with --help").into()),
    }
}

fn cmd_generate(args: &[String]) -> Result<(), Box<dyn Error>> {
    let request_path = required_flag(args, "--request")?;
    let dataset_path = required_flag(args, "--dataset")?;
    let signing_key_path = required_flag(args, "--signing-key")?;

    let request: GenerateRequest = serde_json::from_slice(&read(request_path)?)?;
    let dataset = Dataset::from_json(&read(dataset_path)?)?;
    let key_document: SigningKeyDocument = serde_json::from_slice(&read(signing_key_path)?)?;
    let secret = STANDARD.decode(&key_document.private_key)?;
    let secret: [u8; 32] = secret.try_into().map_err(|bytes: Vec<u8>| {
        format!(
            "privateKey must be standard base64 for exactly 32 bytes, got {}",
            bytes.len()
        )
    })?;
    let signing_key = SigningKey::from_bytes(&secret);

    let generated = generate(&request, &dataset)?;
    let signed = sign_config(generated.body, &signing_key, key_document.key_id.as_deref())?;
    let json = signed.to_json_pretty()?;

    // Self-check the exact bytes before emitting them. Generation never outputs
    // a config that the fail-closed ingest boundary would reject.
    let mut trust_store = TrustStore::new();
    trust_store.insert(signed.signature.key_id.clone(), signing_key.verifying_key())?;
    verify_and_validate_signed_json(&json, &trust_store, &dataset)?;

    let mut stdout = io::stdout().lock();
    stdout.write_all(&json)?;
    stdout.write_all(b"\n")?;
    stdout.flush()?;
    Ok(())
}

fn cmd_verify(args: &[String]) -> Result<(), Box<dyn Error>> {
    let config_path = required_flag(args, "--config")?;
    let dataset_path = required_flag(args, "--dataset")?;
    let trust_store_path = required_flag(args, "--trust-store")?;

    let dataset = Dataset::from_json(&read(dataset_path)?)?;
    let trust_document: TrustStoreDocument = serde_json::from_slice(&read(trust_store_path)?)?;
    let mut trust_store = TrustStore::new();
    for key in trust_document.keys {
        trust_store.insert_base64(key.key_id, &key.public_key)?;
    }
    let signed = verify_and_validate_signed_json(&read(config_path)?, &trust_store, &dataset)?;
    let report = validate(&signed.body, &dataset);
    let output = serde_json::to_vec_pretty(&report)?;
    let mut stdout = io::stdout().lock();
    stdout.write_all(&output)?;
    stdout.write_all(b"\n")?;
    stdout.flush()?;
    Ok(())
}

fn cmd_key_id(args: &[String]) -> Result<(), Box<dyn Error>> {
    let public_key_path = required_flag(args, "--public-key")?;
    let encoded = read_to_string(public_key_path)?;
    let bytes = STANDARD.decode(encoded.trim())?;
    let bytes: [u8; 32] = bytes.try_into().map_err(|bytes: Vec<u8>| {
        format!(
            "public key must be standard base64 for exactly 32 bytes, got {}",
            bytes.len()
        )
    })?;
    let key = ed25519_dalek::VerifyingKey::from_bytes(&bytes)?;
    writeln!(io::stdout().lock(), "{}", derive_key_id(&key))?;
    Ok(())
}

fn required_flag<'a>(args: &'a [String], name: &str) -> Result<&'a str, Box<dyn Error>> {
    let index = args
        .iter()
        .position(|arg| arg == name)
        .ok_or_else(|| format!("missing required {name} <path>"))?;
    args.get(index + 1)
        .map(String::as_str)
        .ok_or_else(|| format!("{name} requires a path").into())
}

fn print_help() {
    println!(
        "Proteus fingerprint engine (M1A)\n\
\n\
         Commands:\n\
           generate --request <json> --dataset <json> --signing-key <json>\n\
           verify   --config <json> --dataset <json> --trust-store <json>\n\
           key-id   --public-key <base64-file>\n\
\n\
         Private keys are read from files, never command-line values. The\n\
         generate command signs and then independently verifies its exact output\n\
         before writing the config to stdout."
    );
}
