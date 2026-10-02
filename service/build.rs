//! API binary does not embed the marketing site or admin SPA.
//! Those are a separate nginx image (`deploy/web`). Keep an empty asset
//! table so `site_asset` still compiles.

use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    let out = match env::var("OUT_DIR") {
        Ok(v) => PathBuf::from(v).join("site_assets.rs"),
        Err(_) => {
            eprintln!("build.rs: OUT_DIR is unset");
            std::process::exit(1);
        }
    };
    let src = "pub static SITE_ASSETS: &[(&str, &str, &[u8])] = &[];\n";
    if let Err(e) = fs::write(&out, src) {
        eprintln!("build.rs: write {}: {e}", out.display());
        std::process::exit(1);
    }
}
