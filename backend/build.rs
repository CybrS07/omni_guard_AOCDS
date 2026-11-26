// Build script. In a RELEASE build for Windows it embeds a manifest that says "this program needs Administrator",
// so Windows shows the normal UAC question and starts the agent elevated by itself. No separate "run as administrator" step.
// Debug builds (npm run dev) are left alone: dev.cjs already starts the whole stack elevated.
fn main() {
    let windows = std::env::var("CARGO_CFG_TARGET_OS").map(|v| v == "windows").unwrap_or(false);
    let msvc = std::env::var("CARGO_CFG_TARGET_ENV").map(|v| v == "msvc").unwrap_or(false);
    let release = std::env::var("PROFILE").map(|v| v == "release").unwrap_or(false);
    if windows && msvc && release {
        println!("cargo:rustc-link-arg-bins=/MANIFEST:EMBED");
        println!("cargo:rustc-link-arg-bins=/MANIFESTUAC:level='requireAdministrator' uiAccess='false'");
    }
    println!("cargo:rerun-if-changed=build.rs");
}
