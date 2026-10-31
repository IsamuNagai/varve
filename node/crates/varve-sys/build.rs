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
            if !p.join("lib/librandomx.a").exists() || !p.join("lib/liboqs.a").exists() {
                let ok = Command::new("sh").arg(&script).arg(&p).status().expect("run tools/build-deps.sh");
                assert!(ok.success(), "tools/build-deps.sh failed");
            }
            p
        }
    };
    for lib in ["liboqs.a", "librandomx.a"] {
        assert!(prefix.join("lib").join(lib).exists(), "missing {} in {}", lib, prefix.display());
    }
    println!("cargo:rustc-link-search=native={}", prefix.join("lib").display());
    println!("cargo:rustc-link-lib=static=oqs");
    println!("cargo:rustc-link-lib=static=randomx");
    let target = env::var("CARGO_CFG_TARGET_OS").unwrap();
    match target.as_str() {
        "macos" | "ios" | "freebsd" | "openbsd" => println!("cargo:rustc-link-lib=dylib=c++"),
        "windows" => {}
        _ => {
            println!("cargo:rustc-link-lib=dylib=stdc++");
            println!("cargo:rustc-link-lib=dylib=pthread");
        }
    }
}
