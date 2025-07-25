use chrono::{DateTime, Utc};
use rust_decimal::Decimal;
use sqlx::{Row, Sqlite, Postgres};
use crate::storage::{UsageQuery, UsageRecord};

/// Dynamic query builder that eliminates pattern matching complexity
pub struct UsageQueryBuilder {
    sql: String,
    params: Vec<QueryParam>,
}

#[derive(Debug)]
pub enum QueryParam {
    Int(i32),
    String(String),
    Bool(bool),
    DateTime(DateTime<Utc>),
    Long(i64),
}

impl Default for UsageQueryBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl UsageQueryBuilder {
    pub fn new() -> Self {
        Self {
            sql: "SELECT id, user_id, model_id, endpoint_type, region, request_time, input_tokens, output_tokens, total_tokens, response_time_ms, success, error_message, cost_usd FROM usage_records".to_string(),
            params: Vec::new(),
        }
    }
    
    pub fn filter_user(mut self, user_id: i32) -> Self {
        self.add_where_condition("user_id = ?");
        self.params.push(QueryParam::Int(user_id));
        self
    }
    
    pub fn filter_model(mut self, model_id: &str) -> Self {
        self.add_where_condition("model_id = ?");
        self.params.push(QueryParam::String(model_id.to_string()));
        self
    }
    
    pub fn filter_success(mut self, success: bool) -> Self {
        self.add_where_condition("success = ?");
        self.params.push(QueryParam::Bool(success));
        self
    }
    
    pub fn filter_date_range(mut self, start: DateTime<Utc>, end: DateTime<Utc>) -> Self {
        self.add_where_condition("request_time >= ?");
        self.params.push(QueryParam::DateTime(start));
        self.add_where_condition("request_time <= ?");
        self.params.push(QueryParam::DateTime(end));
        self
    }
    
    pub fn order_by_time_desc(mut self) -> Self {
        self.sql.push_str(" ORDER BY request_time DESC");
        self
    }
    
    pub fn paginate(mut self, limit: Option<u32>, offset: Option<u32>) -> Self {
        self.sql.push_str(" LIMIT ?");
        self.params.push(QueryParam::Long(limit.unwrap_or(100) as i64));
        self.sql.push_str(" OFFSET ?");
        self.params.push(QueryParam::Long(offset.unwrap_or(0) as i64));
        self
    }
    
    fn add_where_condition(&mut self, condition: &str) {
        if self.sql.contains(" WHERE ") {
            self.sql.push_str(" AND ");
        } else {
            self.sql.push_str(" WHERE ");
        }
        self.sql.push_str(condition);
    }
    
    pub fn build_query(self) -> (String, Vec<QueryParam>) {
        (self.sql, self.params)
    }
    
    /// Execute the query with proper parameter binding for SQLite
    pub async fn execute_sqlite(self, pool: &sqlx::Pool<Sqlite>) -> Result<Vec<UsageRecord>, sqlx::Error> {
        let (sql, params) = self.build_query();
        
        // Create the query with proper binding
        let mut query = sqlx::query(&sql);
        
        // Bind parameters in order
        for param in params {
            match param {
                QueryParam::Int(val) => query = query.bind(val),
                QueryParam::String(val) => query = query.bind(val),
                QueryParam::Bool(val) => query = query.bind(val),
                QueryParam::DateTime(val) => query = query.bind(val),
                QueryParam::Long(val) => query = query.bind(val),
            }
        }
        
        let rows = query.fetch_all(pool).await?;
        
        let records = rows
            .into_iter()
            .map(|row| UsageRecord {
                id: Some(row.get("id")),
                user_id: row.get("user_id"),
                model_id: row.get("model_id"),
                endpoint_type: row.get("endpoint_type"),
                region: row.get("region"),
                request_time: row.get("request_time"),
                input_tokens: row.get::<i32, _>("input_tokens") as u32,
                output_tokens: row.get::<i32, _>("output_tokens") as u32,
                total_tokens: row.get::<i32, _>("total_tokens") as u32,
                response_time_ms: row.get::<i32, _>("response_time_ms") as u32,
                success: row.get("success"),
                error_message: row.get("error_message"),
                cost_usd: row.get::<Option<f64>, _>("cost_usd").and_then(Decimal::from_f64_retain),
            })
            .collect();
        
        Ok(records)
    }
    
    /// Execute the query with proper parameter binding for PostgreSQL
    pub async fn execute_postgres(self, pool: &sqlx::Pool<Postgres>) -> Result<Vec<UsageRecord>, sqlx::Error> {
        let (sql, params) = self.build_query();
        
        // Convert ? placeholders to $1, $2, etc. for PostgreSQL
        let mut pg_sql = sql.clone();
        let mut bind_count = 1;
        while let Some(pos) = pg_sql.find('?') {
            pg_sql.replace_range(pos..pos+1, &format!("${}", bind_count));
            bind_count += 1;
        }
        
        // Create the query with proper binding
        let mut query = sqlx::query(&pg_sql);
        
        // Bind parameters in order
        for param in params {
            match param {
                QueryParam::Int(val) => query = query.bind(val),
                QueryParam::String(val) => query = query.bind(val),
                QueryParam::Bool(val) => query = query.bind(val),
                QueryParam::DateTime(val) => query = query.bind(val),
                QueryParam::Long(val) => query = query.bind(val),
            }
        }
        
        let rows = query.fetch_all(pool).await?;
        
        let records = rows
            .into_iter()
            .map(|row| UsageRecord {
                id: Some(row.get("id")),
                user_id: row.get("user_id"),
                model_id: row.get("model_id"),
                endpoint_type: row.get("endpoint_type"),
                region: row.get("region"),
                request_time: row.get("request_time"),
                input_tokens: row.get::<i32, _>("input_tokens") as u32,
                output_tokens: row.get::<i32, _>("output_tokens") as u32,
                total_tokens: row.get::<i32, _>("total_tokens") as u32,
                response_time_ms: row.get::<i32, _>("response_time_ms") as u32,
                success: row.get("success"),
                error_message: row.get("error_message"),
                cost_usd: row.get("cost_usd"),
            })
            .collect();
        
        Ok(records)
    }
}

/// Helper for building queries from UsageQuery
pub struct UsageQueryHelper;

impl UsageQueryHelper {
    pub fn build_query(query: &UsageQuery) -> UsageQueryBuilder {
        let mut builder = UsageQueryBuilder::new();
        
        // Apply filters based on query parameters
        if let Some(user_id) = query.user_id {
            builder = builder.filter_user(user_id);
        }
        
        if let Some(ref model_id) = query.model_id {
            builder = builder.filter_model(model_id);
        }
        
        if let Some(success) = query.success_only {
            builder = builder.filter_success(success);
        }
        
        if let (Some(start), Some(end)) = (query.start_date, query.end_date) {
            builder = builder.filter_date_range(start, end);
        }
        
        builder
            .order_by_time_desc()
            .paginate(query.limit, query.offset)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use crate::storage::{DatabaseStorage, database::SqliteStorage};

    #[test]
    fn test_query_builder_sql_generation() {
        let builder = UsageQueryBuilder::new()
            .filter_user(123)
            .filter_model("test-model")
            .filter_success(true)
            .order_by_time_desc()
            .paginate(Some(10), Some(0));

        let (sql, params) = builder.build_query();
        
        assert!(sql.contains("SELECT id, user_id, model_id"));
        assert!(sql.contains("FROM usage_records"));
        assert!(sql.contains("WHERE user_id = ?"));
        assert!(sql.contains("AND model_id = ?"));
        assert!(sql.contains("AND success = ?"));
        assert!(sql.contains("ORDER BY request_time DESC"));
        assert!(sql.contains("LIMIT ?"));
        assert!(sql.contains("OFFSET ?"));
        
        assert_eq!(params.len(), 5);
    }

    #[test]
    fn test_query_builder_date_range() {
        let start = Utc::now();
        let end = start + chrono::Duration::hours(1);
        
        let builder = UsageQueryBuilder::new()
            .filter_date_range(start, end)
            .paginate(Some(10), Some(0));

        let (sql, params) = builder.build_query();
        
        assert!(sql.contains("WHERE request_time >= ?"));
        assert!(sql.contains("AND request_time <= ?"));
        assert!(sql.contains("LIMIT ?"));
        assert!(sql.contains("OFFSET ?"));
        assert_eq!(params.len(), 4); // 2 for date range + 2 for pagination
    }

    #[test]
    fn test_postgres_parameter_conversion() {
        let builder = UsageQueryBuilder::new()
            .filter_user(456)
            .filter_model("postgres-test-model")
            .filter_success(false)
            .order_by_time_desc()
            .paginate(Some(10), Some(0));

        let (original_sql, params) = builder.build_query();
        
        // Test the PostgreSQL parameter conversion logic
        let mut pg_sql = original_sql.clone();
        let mut bind_count = 1;
        while let Some(pos) = pg_sql.find('?') {
            pg_sql.replace_range(pos..pos+1, &format!("${}", bind_count));
            bind_count += 1;
        }
        
        assert!(!pg_sql.contains('?')); // Should have no ? left
        assert!(pg_sql.contains("$1")); // Should have $1, $2, etc.
        assert!(pg_sql.contains("$2"));
        assert!(pg_sql.contains("$3"));
        
        // Count parameter placeholders should match actual params
        let dollar_count = (1..10).filter(|i| pg_sql.contains(&format!("${}", i))).count();
        assert_eq!(dollar_count, params.len()); // Should match actual parameter count
        assert_eq!(params.len(), 5); // user_id, model_id, success, limit, offset
    }

    #[test]
    fn test_usage_query_helper() {
        let query = UsageQuery {
            user_id: Some(789),
            model_id: Some("helper-test-model".to_string()),
            start_date: Some(Utc::now() - chrono::Duration::hours(1)),
            end_date: Some(Utc::now()),
            success_only: Some(true),
            limit: Some(20),
            offset: Some(10),
        };

        let builder = UsageQueryHelper::build_query(&query);
        let (sql, params) = builder.build_query();
        
        // Verify all filters are applied
        assert!(sql.contains("WHERE user_id = ?"));
        assert!(sql.contains("AND model_id = ?"));
        assert!(sql.contains("AND success = ?"));
        assert!(sql.contains("AND request_time >= ?"));
        assert!(sql.contains("AND request_time <= ?"));
        assert!(sql.contains("ORDER BY request_time DESC"));
        assert!(sql.contains("LIMIT ?"));
        assert!(sql.contains("OFFSET ?"));
        
        assert_eq!(params.len(), 7); // All filters + pagination
    }

    #[test]
    fn test_minimal_query() {
        let query = UsageQuery {
            user_id: None,
            model_id: None,
            start_date: None,
            end_date: None,
            success_only: None,
            limit: None,
            offset: None,
        };

        let builder = UsageQueryHelper::build_query(&query);
        let (sql, params) = builder.build_query();
        
        // Should only have ORDER BY and default pagination
        assert!(!sql.contains("WHERE"));
        assert!(sql.contains("ORDER BY request_time DESC"));
        assert!(sql.contains("LIMIT ?"));
        assert!(sql.contains("OFFSET ?"));
        
        assert_eq!(params.len(), 2); // Just limit and offset
    }

    #[tokio::test]
    async fn test_sqlite_query_execution() {
        let db = SqliteStorage::new("sqlite::memory:").await.unwrap();
        db.migrate().await.unwrap();

        // Create test data first
        let user = crate::storage::UserRecord {
            id: None,
            provider: "google".to_string(),
            provider_user_id: "query-test-user".to_string(),
            email: "querytest@example.com".to_string(),
            display_name: Some("Query Test User".to_string()),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            last_login: Some(Utc::now()),
        };
        let user_id = db.upsert_user(&user).await.unwrap();

        let usage_record = crate::storage::UsageRecord {
            id: None,
            user_id,
            model_id: "query-builder-test-sqlite".to_string(),
            endpoint_type: "bedrock".to_string(),
            region: "us-east-1".to_string(),
            request_time: Utc::now(),
            input_tokens: 150,
            output_tokens: 75,
            total_tokens: 225,
            response_time_ms: 300,
            success: true,
            error_message: None,
            cost_usd: Some(Decimal::from_f64_retain(0.01125).unwrap_or_default()),
        };
        db.store_usage_record(&usage_record).await.unwrap();

        // Test query execution through the public API
        let query = crate::storage::UsageQuery {
            user_id: Some(user_id),
            model_id: None,
            start_date: None,
            end_date: None,
            success_only: Some(true),
            limit: Some(5),
            offset: Some(0),
        };

        let records = db.get_usage_records(&query).await.unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].model_id, "query-builder-test-sqlite");
        assert_eq!(records[0].input_tokens, 150);
        assert_eq!(records[0].output_tokens, 75);
        assert!(records[0].success);
    }

    #[tokio::test]
    async fn test_postgres_query_execution() {
        let test_db = crate::storage::postgres::tests::create_test_postgres_db().await
            .expect("PostgreSQL database must be available for testing. Set POSTGRES_ADMIN_URL or ensure PostgreSQL is running.");
        let db = &test_db.db;
        
        db.migrate().await.unwrap();

        // Create test data first
        let user = crate::storage::UserRecord {
            id: None,
            provider: "google".to_string(),
            provider_user_id: "query-test-user-pg".to_string(),
            email: "querytestpg@example.com".to_string(),
            display_name: Some("Query Test User PG".to_string()),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            last_login: Some(Utc::now()),
        };
        let user_id = db.upsert_user(&user).await.unwrap();

        let usage_record = crate::storage::UsageRecord {
            id: None,
            user_id,
            model_id: "query-builder-test-postgres".to_string(),
            endpoint_type: "anthropic".to_string(),
            region: "us-west-2".to_string(),
            request_time: Utc::now(),
            input_tokens: 250,
            output_tokens: 125,
            total_tokens: 375,
            response_time_ms: 400,
            success: true,
            error_message: None,
            cost_usd: Some(Decimal::from_f64_retain(0.01875).unwrap_or_default()),
        };
        db.store_usage_record(&usage_record).await.unwrap();

        // Test PostgreSQL query execution through public API (tests our parameter conversion)
        let query = crate::storage::UsageQuery {
            user_id: Some(user_id),
            model_id: Some("query-builder-test-postgres".to_string()),
            start_date: None,
            end_date: None,
            success_only: Some(true),
            limit: Some(10),
            offset: Some(0),
        };

        let records = db.get_usage_records(&query).await.unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].model_id, "query-builder-test-postgres");
        assert_eq!(records[0].input_tokens, 250);
        assert_eq!(records[0].output_tokens, 125);
        assert_eq!(records[0].endpoint_type, "anthropic");
        assert!(records[0].success);
        // Use approximate comparison due to floating point precision
        let expected_cost = Decimal::from_f64_retain(0.01875).unwrap_or_default();
        let actual_cost = records[0].cost_usd.unwrap_or_default();
        let diff = (actual_cost - expected_cost).abs();
        assert!(diff < Decimal::from_f64_retain(0.0001).unwrap_or_default(), 
            "Expected cost {}, got {}, diff {}", expected_cost, actual_cost, diff);
        
    }

    #[tokio::test]
    async fn test_postgres_complex_query() {
        let test_db = crate::storage::postgres::tests::create_test_postgres_db().await
            .expect("PostgreSQL database must be available for testing. Set POSTGRES_ADMIN_URL or ensure PostgreSQL is running.");
        let db = &test_db.db;
        
        db.migrate().await.unwrap();

        // Create test user
        let user = crate::storage::UserRecord {
            id: None,
            provider: "github".to_string(),
            provider_user_id: "complex-query-user".to_string(),
            email: "complexquery@example.com".to_string(),
            display_name: Some("Complex Query User".to_string()),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            last_login: Some(Utc::now()),
        };
        let user_id = db.upsert_user(&user).await.unwrap();

        // Create multiple usage records with different characteristics
        let now = Utc::now();
        let models = ["anthropic.claude-3-sonnet-20240229-v1:0", "anthropic.claude-3-haiku-20240307-v1:0"];
        
        for (i, model) in models.iter().enumerate() {
            let record = crate::storage::UsageRecord {
                id: None,
                user_id,
                model_id: model.to_string(),
                endpoint_type: if i % 2 == 0 { "bedrock" } else { "anthropic" }.to_string(),
                region: "eu-west-1".to_string(),
                request_time: now - chrono::Duration::minutes(i as i64 * 5),
                input_tokens: (i + 1) as u32 * 100,
                output_tokens: (i + 1) as u32 * 50,
                total_tokens: (i + 1) as u32 * 150,
                response_time_ms: 200 + (i as u32 * 50),
                success: i % 2 == 0, // Alternate success/failure
                error_message: if i % 2 == 0 { None } else { Some("Complex query test error".to_string()) },
                cost_usd: Some(Decimal::from_f64_retain((i + 1) as f64 * 0.0075).unwrap_or_default()),
            };
            db.store_usage_record(&record).await.unwrap();
        }

        // Test complex query with multiple filters and date range through public API
        let start_time = now - chrono::Duration::minutes(10);
        let end_time = now + chrono::Duration::minutes(1);
        
        let query1 = crate::storage::UsageQuery {
            user_id: Some(user_id),
            model_id: None,
            start_date: Some(start_time),
            end_date: Some(end_time),
            success_only: Some(true),
            limit: Some(5),
            offset: Some(0),
        };

        let records = db.get_usage_records(&query1).await.unwrap();
        
        // Should only get successful records within date range
        assert_eq!(records.len(), 1);
        assert!(records[0].success);
        assert_eq!(records[0].model_id, "anthropic.claude-3-sonnet-20240229-v1:0");
        assert_eq!(records[0].input_tokens, 100);
        
        // Test filter by specific model
        let query2 = crate::storage::UsageQuery {
            user_id: Some(user_id),
            model_id: Some("anthropic.claude-3-haiku-20240307-v1:0".to_string()),
            start_date: None,
            end_date: None,
            success_only: None,
            limit: Some(5),
            offset: Some(0),
        };

        let records2 = db.get_usage_records(&query2).await.unwrap();
        assert_eq!(records2.len(), 1);
        assert_eq!(records2[0].model_id, "anthropic.claude-3-haiku-20240307-v1:0");
        assert!(!records2[0].success); // This should be the failed record
        
    }
}

