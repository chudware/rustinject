fn main() {
    let mut build = cc::Build::new();
    build.cpp(true).file("native/shellcode.cpp").include("native");

    if std::env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default() == "msvc" {
        build.flag("/Od");
    } else {
        build.flag("-O0");
    }

    build.compile("shellcode");
    println!("cargo:rerun-if-changed=native/shellcode.cpp");
    println!("cargo:rerun-if-changed=native/shellcode.h");
}
