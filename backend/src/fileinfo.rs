//! Step 1 of the download check: read everything useful out of the file.
//!   name, size, SHA-256 hash (what VirusTotal looks files up by),
//!   product / company / version (what the NVD vulnerability database is searched by),
//!   digital signature (is it signed by a real publisher, and by whom).
//! The hash is calculated here in Rust; version and signature come from Windows via PowerShell.

use crate::util::powershell;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::Read;
use std::path::Path;

#[derive(Serialize, Deserialize, Clone, Default, Debug)]
pub struct FileInfo {
    pub name: String,
    pub size: u64,
    pub sha256: String,
    pub product: String,
    pub company: String,
    pub description: String,
    pub version: String,
    pub original_name: String,
    /// true only when Windows says the signature is valid
    pub signed: bool,
    pub signature_status: String,
    pub signer: String,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "PascalCase", default)]
struct Raw {
    product: Option<String>,
    company: Option<String>,
    description: Option<String>,
    file_version: Option<String>,
    product_version: Option<String>,
    original_name: Option<String>,
    sig_status: Option<String>,
    signer: Option<String>,
}

/// Reads the details of a downloaded file: its name, size and SHA-256 hash, plus publisher, version and signature on Windows.
pub fn extract(path: &Path) -> Result<FileInfo, String> {
    let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let (sha256, size) = hash_file(path).map_err(|e| format!("cannot read {name}: {e}"))?;
    let mut info = FileInfo { name: name.clone(), size, sha256, signature_status: "Unknown".into(), ..Default::default() };

    if cfg!(windows) {
        if let Some(raw) = windows_details(path) {
            let pick = |a: Option<String>| a.map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
            info.product = pick(raw.product).unwrap_or_default();
            info.company = pick(raw.company).unwrap_or_default();
            info.description = pick(raw.description).unwrap_or_default();
            info.version = pick(raw.product_version).or_else(|| pick(raw.file_version)).unwrap_or_default();
            info.original_name = pick(raw.original_name).unwrap_or_default();
            info.signature_status = pick(raw.sig_status).unwrap_or_else(|| "Unknown".into());
            info.signed = info.signature_status == "Valid";
            info.signer = pick(raw.signer).unwrap_or_default();
        }
    }
    // Installers often carry no version resource: fall back to "app-name-1.2.3.exe".
    let (guess_product, guess_version) = guess_from_name(&name);
    if info.product.is_empty() {
        info.product = guess_product;
    }
    if info.version.is_empty() {
        info.version = guess_version;
    }
    Ok(info)
}

/// SHA-256 of the whole file, read in 1 MB pieces (large installers are fine).
pub fn hash_file(path: &Path) -> std::io::Result<(String, u64)> {
    let mut f = std::fs::File::open(path)?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    let mut total = 0u64;
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
        total += n as u64;
    }
    Ok((h.finalize().iter().map(|b| format!("{b:02x}")).collect(), total))
}

/// Asks Windows PowerShell for the file's version info and digital signature; returns None if that fails.
fn windows_details(path: &Path) -> Option<Raw> {
    // The path travels in an environment variable, never inside the script text.
    let script = r#"$p=$env:F_PATH
$v=(Get-Item -LiteralPath $p).VersionInfo
$s=Get-AuthenticodeSignature -LiteralPath $p
$signer=''
if($s.SignerCertificate){$signer=[string]$s.SignerCertificate.Subject}
[pscustomobject]@{Product=[string]$v.ProductName;Company=[string]$v.CompanyName;Description=[string]$v.FileDescription;FileVersion=[string]$v.FileVersion;ProductVersion=[string]$v.ProductVersion;OriginalName=[string]$v.OriginalFilename;SigStatus=[string]$s.Status;Signer=$signer}|ConvertTo-Json -Compress"#;
    let p = path.to_string_lossy();
    let out = powershell(script, &[("F_PATH", p.as_ref())], 45)?;
    if !out.ok {
        return None;
    }
    serde_json::from_str(out.stdout.trim()).ok()
}

/// "Notepad++ Setup 8.6.2.exe" -> ("Notepad++", "8.6.2"); "7-Zip 19.00.exe" -> ("7-Zip", "19.00")
pub fn guess_from_name(file_name: &str) -> (String, String) {
    const NOISE: [&str; 9] = ["setup", "installer", "install", "x64", "x86", "win64", "win32", "amd64", "msi"];
    let stem = file_name.rsplit_once('.').map(|(s, _)| s).unwrap_or(file_name);
    let is_version = |w: &str| {
        let w = w.trim_start_matches(|c| c == 'v' || c == 'V');
        w.contains('.') && w.chars().all(|c| c.is_ascii_digit() || c == '.') && w.chars().next().map_or(false, |c| c.is_ascii_digit())
    };
    // Split on spaces and underscores. A '-' only separates words when what follows is a version or
    // noise ("vlc-3.0.20-win64"), so names that contain hyphens ("7-Zip") stay in one piece.
    let mut words: Vec<String> = Vec::new();
    for chunk in stem.split(|c: char| c == ' ' || c == '_').filter(|w| !w.is_empty()) {
        let mut cur = String::new();
        for part in chunk.split('-') {
            let starts_new = part.chars().next().map_or(false, |c| c.is_ascii_digit() || c == 'v' || c == 'V') && is_version(part) || NOISE.contains(&part.to_lowercase().as_str());
            if starts_new && !cur.is_empty() {
                words.push(std::mem::take(&mut cur));
            }
            if !cur.is_empty() {
                cur.push('-');
            }
            cur.push_str(part);
        }
        if !cur.is_empty() {
            words.push(cur);
        }
    }
    let version = words.iter().find(|w| is_version(w)).map(|w| w.trim_start_matches(|c| c == 'v' || c == 'V').to_string()).unwrap_or_default();
    let product = words
        .iter()
        .take_while(|w| !is_version(w))
        .filter(|w| !NOISE.contains(&w.to_lowercase().as_str()))
        .cloned()
        .collect::<Vec<_>>()
        .join(" ");
    (product, version)
}
