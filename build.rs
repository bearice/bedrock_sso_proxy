use std::path::Path;
use std::process::Command;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    build_frontend();

    // Build AWS pricing data
    if let Err(e) = build_pricing_data().await {
        println!("cargo:warning=Failed to build pricing data: {}", e);
    }

    // Tell cargo to re-run this build script if files change
    println!("cargo:rerun-if-changed=frontend/src");
    println!("cargo:rerun-if-changed=frontend/package.json");
    println!("cargo:rerun-if-changed=frontend/vite.config.ts");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=BEDROCK_FETCH_PRICING");

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
    println!("cargo:warning=Building frontend in {} mode...", build_mode);

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

    // Build the frontend with appropriate mode
    println!(
        "cargo:warning=Building frontend assets in {} mode...",
        build_mode
    );
    let build_command = if is_debug { "build:debug" } else { "build" };

    let build_result = Command::new("npm")
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
                "cargo:warning=Frontend build completed successfully in {} mode",
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

/// Build AWS pricing data for fallback prices
async fn build_pricing_data() -> Result<(), Box<dyn std::error::Error>> {
    use std::env;
    use std::path::Path;

    let pricing_json_path = Path::new("aws_pricing.json");

    // Check if we should fetch fresh pricing data
    let should_fetch = env::var("BEDROCK_FETCH_PRICING").is_ok()
        || env::var("PROFILE").unwrap_or_default() == "release"
        || !pricing_json_path.exists()
        || is_file_too_old(pricing_json_path, 30)?;

    if should_fetch {
        println!("cargo:warning=Fetching AWS Bedrock pricing data...");

        fetch_and_save_pricing_json(pricing_json_path)
            .await
            .expect("");
    }
    // Tell cargo to watch the pricing directory
    println!("cargo:rerun-if-changed=pricing/");

    Ok(())
}

/// Check if file is older than specified days
fn is_file_too_old(
    path: &std::path::Path,
    max_age_days: u64,
) -> Result<bool, Box<dyn std::error::Error>> {
    let metadata = std::fs::metadata(path)?;
    let modified = metadata.modified()?;
    let age = std::time::SystemTime::now().duration_since(modified)?;
    let max_age = std::time::Duration::from_secs(max_age_days * 24 * 60 * 60);
    Ok(age > max_age)
}

/// Fetch pricing data from AWS and save as JSON
async fn fetch_and_save_pricing_json(
    json_path: &std::path::Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let client = reqwest::Client::new();
    let pricing_url =
        "https://pricing.us-east-1.amazonaws.com/offers/v1.0/aws/AmazonBedrock/current/index.json";

    println!(
        "cargo:warning=Downloading AWS Bedrock pricing from: {}",
        pricing_url
    );

    let response = client
        .get(pricing_url)
        .timeout(std::time::Duration::from_secs(120))
        .send()
        .await?;

    if !response.status().is_success() {
        return Err(format!("AWS Pricing API returned status: {}", response.status()).into());
    }

    let pricing_data: serde_json::Value = response.json().await?;

    // Save the raw JSON data
    std::fs::write(json_path, serde_json::to_string_pretty(&pricing_data)?)?;

    println!(
        "cargo:warning=Successfully saved AWS pricing data to: {}",
        json_path.display()
    );

    Ok(())
}
