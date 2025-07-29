use std::path::Path;
use std::process::Command;

#[cfg(windows)]
const NPM_CMD: &str = "npm.cmd";
#[cfg(not(windows))]
const NPM_CMD: &str = "npm";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    build_frontend();
    embed_csv_modified_time();

    // Tell cargo to re-run this build script if files change
    println!("cargo:rerun-if-changed=frontend/src");
    println!("cargo:rerun-if-changed=frontend/package.json");
    println!("cargo:rerun-if-changed=frontend/vite.config.ts");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=bedrock_pricing.csv");

    Ok(())
}

fn build_frontend() {
    let frontend_dir = Path::new("frontend");

    if !frontend_dir.exists() {
        println!("cargo:warning=Frontend directory not found, skipping frontend build");
        return;
    }

    // Determine build mode based on Cargo profile
    let is_debug = std::env::var("DEBUG").unwrap_or_else(|_| "false".to_string()) == "true"
        || std::env::var("PROFILE").unwrap_or_else(|_| "release".to_string()) == "debug";

    let build_mode = if is_debug { "debug" } else { "release" };
    println!("cargo:info=Building frontend in {} mode...", build_mode);

    // Check if npm is available
    let npm_check = Command::new(NPM_CMD).arg("--version").output();

    if npm_check.is_err() {
        println!("cargo:warning=npm not found, skipping frontend build");
        return;
    }

    // Install dependencies if node_modules doesn't exist
    if !frontend_dir.join("node_modules").exists() {
        println!("cargo:warning=Installing frontend dependencies...");
        let install_result = Command::new(NPM_CMD)
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

    // Build the frontend with appropriate mode
    println!(
        "cargo:info=Building frontend assets in {} mode...",
        build_mode
    );
    let build_command = if is_debug { "build:debug" } else { "build" };

    let build_result = Command::new(NPM_CMD)
        .arg("run")
        .arg(build_command)
        .current_dir(frontend_dir)
        .env(
            "NODE_ENV",
            if is_debug {
                "development"
            } else {
                "production"
            },
        )
        .output();

    match build_result {
        Ok(output) if output.status.success() => {
            println!(
                "cargo:info=Frontend build completed successfully in {} mode",
                build_mode
            );
        }
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            panic!(
                "Frontend build failed with exit code: {:?}\nSTDOUT:\n{}\nSTDERR:\n{}",
                output.status.code(),
                stdout,
                stderr
            );
        }
        Err(e) => {
            panic!("Failed to run frontend build: {}", e);
        }
    }
}

fn embed_csv_modified_time() {
    let csv_path = Path::new("bedrock_pricing.csv");

    if let Ok(metadata) = std::fs::metadata(csv_path) {
        if let Ok(modified) = metadata.modified() {
            // Convert to Unix timestamp
            let timestamp = modified
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();

            println!("cargo:rustc-env=BEDROCK_CSV_MODIFIED_TIME={}", timestamp);
            println!("cargo:info=Embedded CSV modification time: {}", timestamp);
        } else {
            println!("cargo:warning=Could not get CSV modification time, using current time");
        }
    } else {
        println!("cargo:warning=bedrock_pricing.csv not found, using current time");
    }
}
