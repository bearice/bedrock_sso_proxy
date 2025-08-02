use bedrock_sso_proxy::cache::CacheManager;
use bedrock_sso_proxy::config::Config;
use bedrock_sso_proxy::database::DatabaseManager;
use bedrock_sso_proxy::database::DatabaseManagerImpl;
use bedrock_sso_proxy::database::entities::{
    ModelCost, PeriodType, UsageRecord, UsageSummary, UserRecord, usage_records, usage_summaries,
};

use chrono::{Duration, TimeZone, Utc};
use clap::{Parser, Subcommand};
use rand::prelude::*;
use rand::{SeedableRng, rng};
use rust_decimal::Decimal;
use std::sync::Arc;

#[derive(Parser)]
#[command(name = "dummy-data-generator")]
#[command(about = "Generate dummy data for testing usage records and summaries")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate usage records
    Records {
        /// Number of records to generate
        #[arg(short, long, default_value = "1000")]
        count: usize,
        /// Days back from now to start generating data
        #[arg(short, long, default_value = "7")]
        days_back: i64,
        /// Number of unique users to simulate
        #[arg(short, long, default_value = "10")]
        users: usize,
        /// Seed for random number generator (for reproducible data)
        #[arg(short, long)]
        seed: Option<u64>,
    },
    /// Generate usage summaries
    Summaries {
        /// Period type to generate
        #[arg(short, long, value_enum, default_value = "daily")]
        period: PeriodTypeArg,
        /// Days back from now to start generating summaries
        #[arg(short, long, default_value = "30")]
        days_back: i64,
        /// Number of unique users to simulate
        #[arg(short, long, default_value = "10")]
        users: usize,
        /// Seed for random number generator
        #[arg(short, long)]
        seed: Option<u64>,
    },
    /// Generate test users
    Users {
        /// Number of users to generate
        #[arg(short, long, default_value = "20")]
        count: usize,
        /// Seed for random number generator
        #[arg(short, long)]
        seed: Option<u64>,
    },
    /// Generate both records and summaries
    All {
        /// Number of records to generate
        #[arg(long, default_value = "5000")]
        record_count: usize,
        /// Days back for records
        #[arg(long, default_value = "30")]
        record_days: i64,
        /// Days back for summaries
        #[arg(long, default_value = "30")]
        summary_days: i64,
        /// Number of unique users
        #[arg(short, long, default_value = "25")]
        users: usize,
        /// Seed for random number generator
        #[arg(short, long)]
        seed: Option<u64>,
    },
    /// Clear all usage data (records and summaries)
    Clear {
        /// Skip confirmation prompt
        #[arg(short, long)]
        force: bool,
        /// Also clear all test users
        #[arg(long)]
        include_users: bool,
    },
}

#[derive(clap::ValueEnum, Clone, Debug)]
enum PeriodTypeArg {
    Hourly,
    Daily,
    Weekly,
    Monthly,
}

impl From<PeriodTypeArg> for PeriodType {
    fn from(arg: PeriodTypeArg) -> Self {
        match arg {
            PeriodTypeArg::Hourly => PeriodType::Hourly,
            PeriodTypeArg::Daily => PeriodType::Daily,
            PeriodTypeArg::Weekly => PeriodType::Weekly,
            PeriodTypeArg::Monthly => PeriodType::Monthly,
        }
    }
}

struct DataGenerator {
    database: Arc<dyn DatabaseManager>,
    users: Vec<UserRecord>,
    model_costs: Vec<ModelCost>,
    rng: StdRng,
}

impl DataGenerator {
    async fn new(
        database: Arc<dyn DatabaseManager>,
        seed: Option<u64>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let rng = if let Some(seed) = seed {
            StdRng::seed_from_u64(seed)
        } else {
            // Use default seeding for now
            StdRng::seed_from_u64(42)
        };

        // Fetch existing users and model costs using DAO methods
        let users = Self::get_all_users_from_db(&database).await?;
        let model_costs = database.model_costs().get_all().await?;

        if users.is_empty() {
            eprintln!(
                "Warning: No users found in database. You can generate test users with 'users' command."
            );
        }

        if model_costs.is_empty() {
            eprintln!(
                "Warning: No model costs found in database. Please run 'cargo run --bin bedrock_proxy -- init' first."
            );
        }

        Ok(Self {
            database,
            users,
            model_costs,
            rng,
        })
    }

    async fn get_all_users_from_db(
        database: &Arc<dyn DatabaseManager>,
    ) -> Result<Vec<UserRecord>, Box<dyn std::error::Error>> {
        // Since there's no get_all() method for users, we'll need to query via SeaORM directly
        use bedrock_sso_proxy::database::entities::users;
        use sea_orm::EntityTrait;

        let users = users::Entity::find()
            .all(database.connection())
            .await
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;

        Ok(users)
    }

    async fn generate_users(&mut self, count: usize) -> Result<(), Box<dyn std::error::Error>> {
        println!("Generating {} test users...", count);

        let providers = ["google", "github", "microsoft", "gitlab"];
        let domains = ["example.com", "test.org", "demo.net", "sample.io"];
        let names = vec![
            "Alice", "Bob", "Charlie", "Diana", "Eve", "Frank", "Grace", "Henry", "Ivy", "Jack",
            "Kate", "Liam", "Maya", "Noah", "Olivia", "Paul", "Quinn", "Ruby", "Sam", "Tara",
            "Uma", "Victor", "Wendy", "Xander", "Yara", "Zoe",
        ];

        for i in 0..count {
            if i % 10 == 0 {
                println!("Generated {} / {} users", i, count);
            }

            let provider = providers.choose(&mut self.rng).unwrap();
            let domain = domains.choose(&mut self.rng).unwrap();
            let name = names.choose(&mut self.rng).unwrap();

            let user_id = self.rng.random_range(100000..999999);
            let provider_user_id = format!("test_{}", user_id);
            let email = format!("{}{}@{}", name.to_lowercase(), user_id, domain);
            let display_name = format!("{} Test{}", name, user_id);

            let now = Utc::now();
            let created_at = now - Duration::days(self.rng.random_range(1..365) as i64);

            let user = UserRecord {
                id: 0, // Will be auto-assigned
                provider_user_id,
                provider: provider.to_string(),
                email,
                display_name: Some(display_name),
                created_at,
                updated_at: created_at,
                last_login: if self.rng.random_bool(0.8) {
                    Some(created_at + Duration::days(self.rng.random_range(1..30) as i64))
                } else {
                    None
                },
            };

            self.database.users().upsert(&user).await?;
        }

        println!("Successfully generated {} test users", count);

        // Update our internal users list
        self.users = Self::get_all_users_from_db(&self.database).await?;

        Ok(())
    }

    async fn generate_usage_records(
        &mut self,
        count: usize,
        days_back: i64,
        max_users: usize,
    ) -> Result<(), Box<dyn std::error::Error>> {
        if self.users.is_empty() {
            return Err("No users available for generating records".into());
        }

        let end_time = Utc::now();
        let start_time = end_time - Duration::days(days_back);

        // Limit users to the specified number
        let users_to_use = if max_users < self.users.len() {
            &self.users[0..max_users]
        } else {
            &self.users
        };

        println!(
            "Generating {} usage records over {} days for {} users...",
            count,
            days_back,
            users_to_use.len()
        );

        // Define realistic model patterns
        let claude_models = [
            "claude-sonnet-4-20250514",
            "claude-3-5-sonnet-20241022",
            "claude-3-5-haiku-20241022",
            "claude-3-opus-20240229",
        ];

        let regions = ["us-east-1", "us-west-2", "eu-central-1", "ap-southeast-1"];
        let endpoint_types = ["invoke", "invoke-with-response-stream"];

        for i in 0..count {
            if i % 100 == 0 {
                println!("Generated {} / {} records", i, count);
            }

            // Generate random timestamp within the range
            let time_diff = end_time.timestamp() - start_time.timestamp();
            let random_offset = self.rng.random_range(0..time_diff);
            let request_time = Utc
                .timestamp_opt(start_time.timestamp() + random_offset, 0)
                .unwrap();

            // Select random user, model, region, endpoint
            let user = users_to_use.choose(&mut self.rng).unwrap();
            let model_id = claude_models.choose(&mut self.rng).unwrap();
            let region = regions.choose(&mut self.rng).unwrap();
            let endpoint_type = endpoint_types.choose(&mut self.rng).unwrap();

            // Generate realistic token counts
            let input_tokens = self.rng.random_range(10..2000);
            let output_tokens = self.rng.random_range(50..4000);

            // Cache tokens (sometimes present)
            let (cache_write_tokens, cache_read_tokens) = if self.rng.random_bool(0.3) {
                (
                    Some(self.rng.random_range(0..500)),
                    if self.rng.random_bool(0.7) {
                        Some(self.rng.random_range(0..1000))
                    } else {
                        None
                    },
                )
            } else {
                (None, None)
            };

            let total_tokens = input_tokens
                + output_tokens
                + cache_write_tokens.unwrap_or(0)
                + cache_read_tokens.unwrap_or(0);

            // Response time (mostly fast, some slow)
            let response_time_ms = if self.rng.random_bool(0.9) {
                self.rng.random_range(500..5000)
            } else {
                self.rng.random_range(5000..30000)
            };

            // Success rate (mostly successful)
            let success = self.rng.random_bool(0.95);
            let error_message = if !success {
                Some(self.generate_random_error())
            } else {
                None
            };

            // Calculate cost based on model costs
            let cost_usd = if success {
                self.calculate_cost(
                    model_id,
                    region,
                    input_tokens,
                    output_tokens,
                    cache_write_tokens,
                    cache_read_tokens,
                )
            } else {
                None
            };

            let record = UsageRecord {
                id: 0, // Will be auto-assigned
                user_id: user.id,
                model_id: model_id.to_string(),
                endpoint_type: endpoint_type.to_string(),
                region: region.to_string(),
                request_time,
                input_tokens,
                output_tokens,
                cache_write_tokens,
                cache_read_tokens,
                total_tokens,
                response_time_ms,
                success,
                error_message,
                cost_usd,
            };

            self.database.usage().store_record(&record).await?;
        }

        println!("Successfully generated {} usage records", count);
        Ok(())
    }

    async fn generate_usage_summaries(
        &mut self,
        period: PeriodType,
        days_back: i64,
        max_users: usize,
    ) -> Result<(), Box<dyn std::error::Error>> {
        if self.users.is_empty() {
            return Err("No users available for generating summaries".into());
        }

        let end_time = Utc::now();
        let start_time = end_time - Duration::days(days_back);

        let users_to_use = if max_users < self.users.len() {
            &self.users[0..max_users]
        } else {
            &self.users
        };

        println!(
            "Generating {} summaries over {} days for {} users...",
            period.as_str(),
            days_back,
            users_to_use.len()
        );

        let claude_models = vec![
            "claude-sonnet-4-20250514",
            "claude-3-5-sonnet-20241022",
            "claude-3-5-haiku-20241022",
        ];

        let mut current_time = period.round_start(start_time);
        let mut summary_count = 0;

        while current_time < end_time {
            let period_end = period.period_end(current_time);

            for user in users_to_use {
                for model_id in &claude_models {
                    // Skip some combinations randomly for realism
                    if self.rng.random_bool(0.7) {
                        continue;
                    }

                    let total_requests = self.rng.random_range(1..100);
                    let successful_requests =
                        (total_requests as f32 * self.rng.random_range(0.85..1.0)) as i32;

                    let total_input_tokens = self.rng.random_range(1000..50000) as i64;
                    let total_output_tokens = self.rng.random_range(2000..100000) as i64;
                    let total_tokens = total_input_tokens + total_output_tokens;

                    let avg_response_time_ms = self.rng.random_range(1000.0..8000.0);

                    // Estimate cost based on total tokens
                    let estimated_cost = Some(Decimal::from(total_tokens) * Decimal::new(25, 6)); // ~$0.000025 per token

                    let summary = UsageSummary {
                        id: 0, // Will be auto-assigned
                        user_id: user.id,
                        model_id: model_id.to_string(),
                        period_type: period,
                        period_start: current_time,
                        period_end,
                        total_requests,
                        successful_requests,
                        total_input_tokens,
                        total_output_tokens,
                        total_tokens,
                        avg_response_time_ms,
                        estimated_cost,
                        created_at: Utc::now(),
                        updated_at: Utc::now(),
                    };

                    self.database
                        .usage()
                        .upsert_many_summaries(&[summary])
                        .await?;
                    summary_count += 1;
                }
            }

            current_time = period_end;
        }

        println!("Successfully generated {} usage summaries", summary_count);
        Ok(())
    }

    async fn clear_usage_data(
        &self,
        force: bool,
        include_users: bool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let what_to_clear = if include_users {
            "ALL usage records, summaries, AND test users"
        } else {
            "ALL usage records and summaries"
        };

        if !force {
            println!("This will delete {}. Are you sure? (y/N)", what_to_clear);
            let mut input = String::new();
            std::io::stdin().read_line(&mut input)?;
            if input.trim().to_lowercase() != "y" {
                println!("Aborted.");
                return Ok(());
            }
        }

        println!("Clearing {}...", what_to_clear);

        // Clear records and summaries using direct SeaORM operations
        use bedrock_sso_proxy::database::entities::users;
        use sea_orm::EntityTrait;

        let records_deleted = usage_records::Entity::delete_many()
            .exec(self.database.connection())
            .await?;

        let summaries_deleted = usage_summaries::Entity::delete_many()
            .exec(self.database.connection())
            .await?;

        println!(
            "Deleted {} usage records and {} summaries",
            records_deleted.rows_affected, summaries_deleted.rows_affected
        );

        if include_users {
            let users_deleted = users::Entity::delete_many()
                .exec(self.database.connection())
                .await?;
            println!("Deleted {} test users", users_deleted.rows_affected);
        }

        println!("Data cleared successfully.");
        Ok(())
    }

    fn calculate_cost(
        &self,
        model_id: &str,
        region: &str,
        input_tokens: i32,
        output_tokens: i32,
        cache_write_tokens: Option<i32>,
        cache_read_tokens: Option<i32>,
    ) -> Option<Decimal> {
        // Try to find exact model cost
        if let Some(cost_data) = self
            .model_costs
            .iter()
            .find(|c| c.model_id == model_id && c.region == region)
        {
            let mut total_cost = Decimal::ZERO;

            // Input and output costs are mandatory
            total_cost += cost_data.input_cost_per_1k_tokens * Decimal::from(input_tokens)
                / Decimal::from(1000);
            total_cost += cost_data.output_cost_per_1k_tokens * Decimal::from(output_tokens)
                / Decimal::from(1000);

            // Cache costs are optional
            if let (Some(cache_write), Some(cache_write_price)) =
                (cache_write_tokens, cost_data.cache_write_cost_per_1k_tokens)
            {
                total_cost += cache_write_price * Decimal::from(cache_write) / Decimal::from(1000);
            }

            if let (Some(cache_read), Some(cache_read_price)) =
                (cache_read_tokens, cost_data.cache_read_cost_per_1k_tokens)
            {
                total_cost += cache_read_price * Decimal::from(cache_read) / Decimal::from(1000);
            }

            Some(total_cost)
        } else {
            // Fallback to estimated cost
            let total_tokens = input_tokens
                + output_tokens
                + cache_write_tokens.unwrap_or(0)
                + cache_read_tokens.unwrap_or(0);
            Some(Decimal::from(total_tokens) * Decimal::new(25, 6)) // ~$0.000025 per token
        }
    }

    fn generate_random_error(&self) -> String {
        let errors = [
            "Rate limit exceeded",
            "Invalid model parameters",
            "Request timeout",
            "Service unavailable",
            "Authentication failed",
            "Token limit exceeded",
            "Internal server error",
        ];
        errors.choose(&mut rng()).unwrap().to_string()
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    // Load configuration
    let config = Config::load()?;

    // Initialize database
    let cache = Arc::new(CacheManager::new_from_config(&config.cache).await?);
    let database = Arc::new(DatabaseManagerImpl::new_from_config(&config, cache).await?);

    match cli.command {
        Commands::Records {
            count,
            days_back,
            users,
            seed,
        } => {
            let mut generator = DataGenerator::new(database, seed).await?;
            generator
                .generate_usage_records(count, days_back, users)
                .await?;
        }
        Commands::Summaries {
            period,
            days_back,
            users,
            seed,
        } => {
            let mut generator = DataGenerator::new(database, seed).await?;
            generator
                .generate_usage_summaries(period.into(), days_back, users)
                .await?;
        }
        Commands::Users { count, seed } => {
            let mut generator = DataGenerator::new(database, seed).await?;
            generator.generate_users(count).await?;
        }
        Commands::All {
            record_count,
            record_days,
            summary_days,
            users,
            seed,
        } => {
            let mut generator = DataGenerator::new(database, seed).await?;

            // Generate users first if none exist
            if generator.users.is_empty() {
                println!("No users found. Generating {} test users first...", users);
                generator.generate_users(users).await?;
            }

            generator
                .generate_usage_records(record_count, record_days, users)
                .await?;
            generator
                .generate_usage_summaries(PeriodType::Daily, summary_days, users)
                .await?;
        }
        Commands::Clear {
            force,
            include_users,
        } => {
            let generator = DataGenerator::new(database, None).await?;
            generator.clear_usage_data(force, include_users).await?;
        }
    }

    Ok(())
}
