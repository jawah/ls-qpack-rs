use std::env;
use std::fs;
use std::path::{Path, PathBuf};

/// Copy a directory recursively, skipping `.git` directories.
fn copy_dir_recursive(src: &Path, dst: &Path) {
    fs::create_dir_all(dst).expect("failed to create directory");
    for entry in fs::read_dir(src).expect("failed to read directory") {
        let entry = entry.expect("failed to read entry");
        let file_type = entry.file_type().expect("failed to get file type");
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());

        if src_path.file_name().map_or(false, |n| n == ".git") {
            continue;
        }

        if file_type.is_dir() {
            copy_dir_recursive(&src_path, &dst_path);
        } else {
            fs::copy(&src_path, &dst_path).expect("failed to copy file");
        }
    }
}

/// Patch cmake_minimum_required from 3.1 to 3.6 to avoid policy
/// deprecation warnings/errors on newer CMake versions.
fn patch_cmakelists(build_dir: &Path) {
    let cmakelists = build_dir.join("CMakeLists.txt");
    let content = fs::read_to_string(&cmakelists).expect("failed to read CMakeLists.txt");
    let patched = content.replace(
        "cmake_minimum_required(VERSION 3.1)",
        "cmake_minimum_required(VERSION 3.6)",
    );
    fs::write(&cmakelists, patched).expect("failed to write patched CMakeLists.txt");
}

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR not set"));
    let ls_qpack_src = Path::new("deps/ls-qpack");

    // Copy the C source tree into OUT_DIR so we can patch it without
    // modifying the git submodule.
    let ls_qpack_build = out_dir.join("ls-qpack-src");
    if ls_qpack_build.exists() {
        fs::remove_dir_all(&ls_qpack_build).expect("failed to clean previous build dir");
    }
    copy_dir_recursive(ls_qpack_src, &ls_qpack_build);
    patch_cmakelists(&ls_qpack_build);

    // Build ls-qpack with CMake from the patched copy
    let dst = cmake::Config::new(&ls_qpack_build)
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

    // Generate bindings (use headers from the patched source tree since
    // cmake installs may not copy all headers we need)
    let bindings = bindgen::Builder::default()
        .derive_debug(true)
        .derive_default(true)
        .size_t_is_usize(true)
        .layout_tests(false)
        .generate_comments(false)
        .clang_arg(format!("-I{}", dst.join("include").display()))
        .header(ls_qpack_build.join("lsqpack.h").to_string_lossy())
        .header(ls_qpack_build.join("lsxpack_header.h").to_string_lossy())
        .generate()
        .expect("Unable to generate bindings");

    bindings
        .write_to_file(out_dir.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
