use std::{env, process::Command};

fn main() {
    compile_port_shim();
}

fn compile_port_shim() {
    println!("cargo:rerun-if-changed=src/port_shim.c");

    // Try PGRX_PG_CONFIG_PATH first, then PG_CONFIG, then default pg_config
    let pg_config_path = env::var("PGRX_PG_CONFIG_PATH")
        .or_else(|_| env::var("PG_CONFIG"))
        .unwrap_or_else(|_| "pg_config".to_string());
    
    let includedir_server = run_pg_config(&pg_config_path, "--includedir-server");
    let includedir = run_pg_config(&pg_config_path, "--includedir");

    let mut build = cc::Build::new();
    build.file("src/port_shim.c");
    build.include(includedir_server.trim());
    build.include(includedir.trim());
    build.flag_if_supported("-Wno-unused-parameter");
    build.flag_if_supported("-Wno-unused-function");
    build.compile("sqlfw_port_shim");
}

fn run_pg_config(pg_config: &str, flag: &str) -> String {
    let output = Command::new(pg_config)
        .arg(flag)
        .output()
        .unwrap_or_else(|err| panic!("failed to run pg_config {flag}: {err}"));
    if !output.status.success() {
        panic!(
            "pg_config {flag} failed with status {:?}",
            output.status.code()
        );
    }
    String::from_utf8(output.stdout).expect("pg_config output is not UTF-8")
}
