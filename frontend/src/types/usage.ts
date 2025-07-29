// Usage Tracking Types

export interface UsageRecord {
  id: number;
  user_id: number;
  model_id: string;
  endpoint_type: string;
  region: string;
  request_time: string;
  input_tokens: number;
  output_tokens: number;
  cache_write_tokens: number | null;
  cache_read_tokens: number | null;
  total_tokens: number;
  response_time_ms: number;
  success: boolean;
  error_message?: string | null;
  cost_usd?: string | null;
}

export interface UsageStats {
  total_requests: number;
  successful_requests: number;
  failed_requests: number;
  total_input_tokens: number;
  total_output_tokens: number;
  total_tokens: number;
  success_rate: number;
  total_cost_cents: number;
  unique_models: number;
  date_range: {
    start: string;
    end: string;
  };
}

export interface UsageQuery {
  limit?: number;
  offset?: number;
  model?: string;
  start_date?: string;
  end_date?: string;
  success_only?: boolean;
  min_tokens?: number;
  max_tokens?: number;
}

export interface UsageStatsQuery {
  start_date?: string;
  end_date?: string;
  model?: string;
  success?: boolean;
}

export interface UsageRecordsResponse {
  records: UsageRecord[];
  total: number;
  limit: number;
  offset: number;
}

export interface ModelUsage {
  model_id: string;
  total_tokens: number;
}

export interface TopModelsResponse {
  models: ModelUsage[];
}

// Usage filter presets
export type UsagePeriod = 'today' | 'week' | 'month' | 'all' | 'custom';

export interface UsageFilters {
  period: UsagePeriod;
  startDate?: Date;
  endDate?: Date;
  model?: string;
  successOnly?: boolean;
}
