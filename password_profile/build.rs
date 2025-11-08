fn main() {
    println!("cargo:rerun-if-changed=src/shim/client_auth.c");

    let mut build = cc::Build::new();
    build.file("src/shim/client_auth.c");

    // Try pgrx environment variables first
    for var in [
        "PGRX_INCLUDEDIR_SERVER",
        "PGRX_INCLUDEDIR_SERVER_PORT_WIN32",
        "PGRX_INCLUDEDIR_SERVER_PORT_WIN32_MSVC",
        "PGRX_INCLUDEDIR",
    ] {
        if let Ok(path) = std::env::var(var) {
            if !path.is_empty() {
                build.include(path);
            }
        }
    }

    // Fallback: use pg_config to get include directory
    if let Ok(output) = std::process::Command::new("pg_config")
        .arg("--includedir-server")
        .output()
    {
        if output.status.success() {
            let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !path.is_empty() {
                build.include(&path);
                println!("cargo:warning=Using pg_config include path: {}", path);
            }
        }
    }

    build.flag_if_supported("-Wno-unused-parameter");
    build.compile("password_profile_client_auth_shim");

    // Link PostgreSQL library when building tests
    if let Ok(output) = std::process::Command::new("pg_config")
        .arg("--libdir")
        .output()
    {
        if output.status.success() {
            let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !path.is_empty() {
                println!("cargo:rustc-link-search=native={}", path);
                println!("cargo:rustc-link-lib=dylib=pq");
            }
        }
    }
}
