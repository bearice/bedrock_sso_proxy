//! Usage data summarization service
//!
//! This module provides background services for aggregating raw usage records
//! into pre-computed summaries for efficient querying.

pub mod aggregator;
pub mod config;
pub mod service;

pub use aggregator::{PeriodType, SummaryAggregator};
pub use config::SummarizationConfig;
pub use service::SummarizationService;
