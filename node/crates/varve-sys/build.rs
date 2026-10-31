//! Links the pinned static C libraries. Uses $VARVE_DEPS if set (a prefix made by
//! tools/build-deps.sh); otherwise runs that script once into OUT_DIR.
use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-env-changed=VARVE_DEPS");
    let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let script = manifest.join("../../../tools/build-deps.sh");
    println!("cargo:rerun-if-changed={}", script.display());
    let prefix = match env::var("VARVE_DEPS") {
        Ok(p) => PathBuf::from(p),
        Err(_) => {
            let p = PathBuf::from(env::var("OUT_DIR").unwrap()).join("deps");
            if !libs_present(&p) {
                let ok = Command::new("sh").arg(&script).arg(&p).status().expect("run tools/build-deps.sh");
                assert!(ok.success(), "tools/build-deps.sh failed");
            }
            p
        }
    };
    assert!(libs_present(&prefix), "missing liboqs/RandomX static libraries in {}", prefix.display());
    println!("cargo:rustc-link-search=native={}", prefix.join("lib").display());
    println!("cargo:rustc-link-lib=static=oqs");
    println!("cargo:rustc-link-lib=static=randomx");
    let target = env::var("CARGO_CFG_TARGET_OS").unwrap();
    match target.as_str() {
        "macos" | "ios" | "freebsd" | "openbsd" => println!("cargo:rustc-link-lib=dylib=c++"),
        "windows" => {
            // liboqs uses the Windows CNG random number generator
            println!("cargo:rustc-link-lib=dylib=bcrypt");
            println!("cargo:rustc-link-lib=dylib=advapi32");
        }
        _ => {
            println!("cargo:rustc-link-lib=dylib=stdc++");
            println!("cargo:rustc-link-lib=dylib=pthread");
        }
    }
}

fn libs_present(prefix: &std::path::Path) -> bool {
    let lib = prefix.join("lib");
    let windows = env::var("CARGO_CFG_TARGET_OS").map(|t| t == "windows").unwrap_or(false);
    let names: [&str; 2] = if windows { ["oqs.lib", "randomx.lib"] } else { ["liboqs.a", "librandomx.a"] };
    names.iter().all(|n| lib.join(n).exists())
}
