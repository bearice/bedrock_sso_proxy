use std::path::Path;
use std::process::Command;

fn main() {
    build_frontend();
    // Tell cargo to re-run this build script if frontend files change
    println!("cargo:rerun-if-changed=frontend/src");
    println!("cargo:rerun-if-changed=frontend/package.json");
    println!("cargo:rerun-if-changed=frontend/vite.config.ts");
}

fn build_frontend() {
    let frontend_dir = Path::new("frontend");

    if !frontend_dir.exists() {
        println!("cargo:warning=Frontend directory not found, skipping frontend build");
        return;
    }

    println!("cargo:warning=Building frontend...");

    // Check if npm is available
    let npm_check = Command::new("npm").arg("--version").output();

    if npm_check.is_err() {
        println!("cargo:warning=npm not found, skipping frontend build");
        return;
    }

    // Install dependencies if node_modules doesn't exist
    if !frontend_dir.join("node_modules").exists() {
        println!("cargo:warning=Installing frontend dependencies...");
        let install_result = Command::new("npm")
            .arg("install")
            .current_dir(frontend_dir)
            .status();

        if let Err(e) = install_result {
            println!(
                "cargo:warning=Failed to install frontend dependencies: {}",
                e
            );
            return;
        }
    }

    // Build the frontend
    println!("cargo:warning=Building frontend assets...");
    let build_result = Command::new("npm")
        .arg("run")
        .arg("build")
        .current_dir(frontend_dir)
        .status();

    match build_result {
        Ok(status) if status.success() => {
            println!("cargo:warning=Frontend build completed successfully");
        }
        Ok(status) => {
            println!(
                "cargo:warning=Frontend build failed with exit code: {:?}",
                status.code()
            );
        }
        Err(e) => {
            println!("cargo:warning=Failed to run frontend build: {}", e);
        }
    }
}
