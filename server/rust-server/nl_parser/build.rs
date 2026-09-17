use std::path::Path;
use std::process::Command;

fn main() {
    let out_dir = std::env::var("OUT_DIR").unwrap();
    let fbs_path = Path::new("../module.fbs");

    println!("cargo:rerun-if-changed=../module.fbs");

    // Prefer local flatc.exe bundled in the crate directory, fall back to PATH
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let local_flatc = Path::new(&manifest_dir).join("flatc.exe");
    let flatc = if local_flatc.exists() {
        local_flatc.to_str().unwrap().to_string()
    } else {
        "flatc".to_string()
    };

    let status = Command::new(&flatc)
        .args(["--rust", "-o", &out_dir, fbs_path.to_str().unwrap()])
        .status()
        .expect("Failed to run flatc. Ensure flatc is in PATH or place flatc.exe in nl_parser/.");

    assert!(status.success(), "flatc exited with error");
}
