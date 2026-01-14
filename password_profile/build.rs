fn main() {
    println!("cargo:rerun-if-changed=src/shim/client_auth.c");

    let mut build = cc::Build::new();
    build.file("src/shim/client_auth.c");

    // Try to get the PostgreSQL include path from pgrx
    let pg_config = get_pg_config_path();
    
    if let Ok(output) = std::process::Command::new(&pg_config)
        .arg("--includedir-server")
        .output()
    {
        if output.status.success() {
            let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !path.is_empty() {
                build.include(&path);
                println!("cargo:warning=Using pg_config ({}) server include path: {}", pg_config, path);
            }
        }
    }
    
    // Also include the main include directory
    if let Ok(output) = std::process::Command::new(&pg_config)
        .arg("--includedir")
        .output()
    {
        if output.status.success() {
            let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !path.is_empty() {
                build.include(&path);
                println!("cargo:warning=Using pg_config ({}) include path: {}", pg_config, path);
            }
        }
    }

    build.flag_if_supported("-Wno-unused-parameter");
    build.compile("password_profile_client_auth_shim");

    // Link PostgreSQL library when building tests
    if let Ok(output) = std::process::Command::new(&pg_config)
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

fn get_pg_config_path() -> String {
    // Priority order:
    // 1. PGRX_PG_CONFIG_PATH (set by cargo-pgrx)
    // 2. PG_CONFIG (manual override)
    // 3. Use pg_config from PATH
    std::env::var("PGRX_PG_CONFIG_PATH")
        .or_else(|_| std::env::var("PG_CONFIG"))
        .unwrap_or_else(|_| {
            // Last resort: try to find pg_config
            "pg_config".to_string()
        })
}
