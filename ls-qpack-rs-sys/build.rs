use std::env;
use std::path::{Path, PathBuf};

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR not set"));
    let ls_qpack_dir = Path::new("deps/ls-qpack");

    // Build ls-qpack with CMake
    let dst = cmake::Config::new(ls_qpack_dir)
        .define("LSQPACK_BIN", "OFF")
        .out_dir(&out_dir)
        .build();

    println!(
        "cargo:rustc-link-search=native={}",
        out_dir.join("lib64").display()
    );
    println!(
        "cargo:rustc-link-search=native={}",
        out_dir.join("lib").display()
    );
    println!("cargo:rustc-link-lib=static=ls-qpack");

    // Generate bindings
    let bindings = bindgen::Builder::default()
        .derive_debug(true)
        .derive_default(true)
        .size_t_is_usize(true)
        .layout_tests(false)
        .generate_comments(false)
        .clang_arg(format!("-I{}", dst.join("include").display()))
        .header(ls_qpack_dir.join("lsqpack.h").to_string_lossy())
        .header(ls_qpack_dir.join("lsxpack_header.h").to_string_lossy())
        .generate()
        .expect("Unable to generate bindings");

    bindings
        .write_to_file(out_dir.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
