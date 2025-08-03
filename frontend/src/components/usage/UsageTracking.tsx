import { useState, useEffect, useCallback } from 'react';
import { useAuth } from '../../hooks/useAuth';
import { usageApi, ApiError } from '../../services/api';
import { UsageQuery, UsageSummary, UsageSummariesQuery } from '../../types/usage';
import { UsageFilters } from './UsageFilters';
import { UsageRecords } from './UsageRecords';
import { UsageSummaryCharts } from './UsageSummaryCharts';
import { Activity, AlertCircle } from 'lucide-react';

export function UsageTracking() {
  const { token } = useAuth();
  const [summaries, setSummaries] = useState<UsageSummary[]>([]);

  const [isLoadingSummaries, setIsLoadingSummaries] = useState(true);
  const [isExporting, setIsExporting] = useState(false);

  const [summariesError, setSummariesError] = useState<string | null>(null);

  // Initialize filters with this month as default
  const getDefaultFilters = useCallback((): UsageQuery => {
    const now = new Date();
    const startOfMonth = new Date(now.getFullYear(), now.getMonth(), 1);

    // Set end date to end of today to include all of today's data
    const endOfToday = new Date(now);
    endOfToday.setHours(23, 59, 59, 999);

    return {
      start_date: startOfMonth.toISOString(),
      end_date: endOfToday.toISOString(),
      limit: 50,
      offset: 0,
    };
  }, []);

  const [filters, setFilters] = useState<UsageQuery>(getDefaultFilters);

  // Intelligent period selection based on date range
  const getOptimalPeriodType = useCallback(
    (startDate: string, endDate: string): 'hourly' | 'daily' | 'weekly' | 'monthly' => {
      const start = new Date(startDate);
      const end = new Date(endDate);
      const daysDiff = Math.ceil((end.getTime() - start.getTime()) / (1000 * 60 * 60 * 24));

      if (daysDiff <= 2) return 'hourly';
      if (daysDiff <= 30) return 'daily';
      if (daysDiff <= 180) return 'weekly';
      return 'monthly';
    },
    []
  );

  // Get the current incomplete period bounds
  const getCurrentPeriodBounds = useCallback((periodType: 'daily' | 'weekly' | 'monthly') => {
    const now = new Date();

    switch (periodType) {
      case 'daily': {
        // Current day from midnight to now in UTC
        const startOfDay = new Date(now);
        startOfDay.setUTCHours(0, 0, 0, 0);
        return {
          start: startOfDay.toISOString(),
          end: now.toISOString(),
          lowerPeriodType: 'hourly' as const,
        };
      }
      case 'weekly': {
        // Current week (Monday to now)
        const startOfWeek = new Date(now);
        const dayOfWeek = startOfWeek.getUTCDay();
        const daysToMonday = (dayOfWeek + 6) % 7; // Convert Sunday=0 to Monday=0
        startOfWeek.setUTCDate(startOfWeek.getUTCDate() - daysToMonday);
        startOfWeek.setUTCHours(0, 0, 0, 0);
        return {
          start: startOfWeek.toISOString(),
          end: now.toISOString(),
          lowerPeriodType: 'daily' as const,
        };
      }
      case 'monthly': {
        // Current month from 1st to now
        const startOfMonth = new Date(now.getUTCFullYear(), now.getUTCMonth(), 1);
        return {
          start: startOfMonth.toISOString(),
          end: now.toISOString(),
          lowerPeriodType: 'daily' as const,
        };
      }
    }
  }, []);

  // Load usage summaries with intelligent period selection
  const loadSummaries = useCallback(async () => {
    if (!token || !filters.start_date || !filters.end_date) return;

    try {
      setIsLoadingSummaries(true);
      setSummariesError(null);

      const optimalPeriodType = getOptimalPeriodType(filters.start_date, filters.end_date);

      // Main query for the optimal period type
      const mainQuery: UsageSummariesQuery = {
        start_date: filters.start_date,
        end_date: filters.end_date,
        model_id: filters.model,
        period_type: optimalPeriodType,
        limit: 1000,
      };

      let allSummaries: UsageSummary[] = [];

      // Get main summaries
      const mainData = await usageApi.getUsageSummaries(token, mainQuery);
      allSummaries = [...mainData.summaries];

      // If we're not using hourly data, check if we need current period data from lower level
      if (optimalPeriodType !== 'hourly') {
        const currentPeriodBounds = getCurrentPeriodBounds(optimalPeriodType);
        const filterEndDate = new Date(filters.end_date);

        // Only fetch lower-level data if the filter end date includes the current incomplete period
        if (filterEndDate >= new Date(currentPeriodBounds.start)) {
          try {
            const currentPeriodQuery: UsageSummariesQuery = {
              start_date: currentPeriodBounds.start,
              end_date: currentPeriodBounds.end,
              model_id: filters.model,
              period_type: currentPeriodBounds.lowerPeriodType,
              limit: 1000,
            };

            const currentPeriodData = await usageApi.getUsageSummaries(token, currentPeriodQuery);

            // Aggregate current period data by model
            if (currentPeriodData.summaries.length > 0) {
              const aggregatedCurrentPeriod: Record<string, UsageSummary> = {};

              currentPeriodData.summaries.forEach((summary) => {
                const modelId = summary.model_id;
                if (!aggregatedCurrentPeriod[modelId]) {
                  aggregatedCurrentPeriod[modelId] = {
                    ...summary,
                    id: Date.now() + Math.random(), // Temporary ID for aggregated data
                    period_type: optimalPeriodType,
                    period_start: currentPeriodBounds.start,
                    period_end: currentPeriodBounds.end,
                    total_requests: 0,
                    successful_requests: 0,
                    total_input_tokens: 0,
                    total_output_tokens: 0,
                    total_tokens: 0,
                    avg_response_time_ms: 0,
                    estimated_cost: '0',
                  };
                }

                const agg = aggregatedCurrentPeriod[modelId];
                agg.total_requests += summary.total_requests;
                agg.successful_requests += summary.successful_requests;
                agg.total_input_tokens += summary.total_input_tokens;
                agg.total_output_tokens += summary.total_output_tokens;
                agg.total_tokens += summary.total_tokens;

                // Weighted average for response time
                const totalRequests = agg.total_requests;
                agg.avg_response_time_ms =
                  totalRequests > 0
                    ? (agg.avg_response_time_ms * (totalRequests - summary.total_requests) +
                        summary.avg_response_time_ms * summary.total_requests) /
                      totalRequests
                    : 0;

                // Sum estimated costs
                const currentCost = parseFloat(agg.estimated_cost || '0');
                const summaryCost = parseFloat(summary.estimated_cost || '0');
                agg.estimated_cost = (currentCost + summaryCost).toString();
              });

              // Remove any existing current period data from main summaries and add aggregated data
              const currentPeriodStart = new Date(currentPeriodBounds.start);
              allSummaries = allSummaries.filter((summary) => {
                const summaryStart = new Date(summary.period_start);
                return summaryStart < currentPeriodStart;
              });

              // Add aggregated current period data
              allSummaries.push(...Object.values(aggregatedCurrentPeriod));
            }
          } catch (currentPeriodError) {
            // If current period fetch fails, log but don't fail the whole operation
            console.warn('Failed to fetch current period data:', currentPeriodError);
          }
        }
      }

      setSummaries(allSummaries);
    } catch (err) {
      console.error('Failed to load usage summaries:', err);
      setSummariesError(err instanceof ApiError ? err.message : 'Failed to load usage summaries');
    } finally {
      setIsLoadingSummaries(false);
    }
  }, [
    token,
    filters.start_date,
    filters.end_date,
    filters.model,
    getOptimalPeriodType,
    getCurrentPeriodBounds,
  ]);

  // Export usage data
  const handleExport = useCallback(async () => {
    if (!token) return;

    try {
      setIsExporting(true);

      const exportQuery = {
        start_date: filters.start_date,
        end_date: filters.end_date,
        model: filters.model,
        success: filters.success_only,
        format: 'csv' as const,
        limit: 10000, // Export up to 10k records
      };

      const blob = await usageApi.exportUsageData(token, exportQuery);

      // Create download link
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = `usage-export-${new Date().toISOString().split('T')[0]}.csv`;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      window.URL.revokeObjectURL(url);
    } catch (err) {
      console.error('Failed to export usage data:', err);
      alert(err instanceof ApiError ? err.message : 'Failed to export usage data');
    } finally {
      setIsExporting(false);
    }
  }, [token, filters.start_date, filters.end_date, filters.model, filters.success_only]);

  // Handle filter changes
  const handleFiltersChange = useCallback((newFilters: UsageQuery) => {
    setFilters(newFilters);
  }, []);

  // Refresh all data
  const refreshData = useCallback(() => {
    loadSummaries();
  }, [loadSummaries]);

  // Initial data load
  useEffect(() => {
    if (token) {
      loadSummaries();
    }
  }, [token, loadSummaries]);

  // Reload when filters change (but not on initial load)
  useEffect(() => {
    if (token) {
      loadSummaries();
    }
  }, [filters, loadSummaries, token]);

  if (!token) {
    return (
      <div style={{ textAlign: 'center', padding: '2rem' }}>
        <AlertCircle size={48} style={{ color: '#dc3545', margin: '0 auto 1rem' }} />
        <h3>Authentication Required</h3>
        <p>Please log in to view your usage tracking data.</p>
      </div>
    );
  }

  return (
    <div>
      {/* Header */}
      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          marginBottom: '2rem',
        }}
      >
        <div>
          <h2 style={{ margin: 0, display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <Activity size={24} />
            Usage Tracking
          </h2>
          <p style={{ margin: '0.5rem 0 0 0', color: '#374151', fontWeight: '500' }}>
            Monitor your API usage, token consumption, and costs
          </p>
        </div>
        <div style={{ display: 'flex', gap: '0.75rem' }}>
          {/* Removed refresh and export buttons - they're now in UsageRecords */}
        </div>
      </div>

      {/* Usage Summary Charts */}
      <UsageSummaryCharts
        summaries={summaries}
        isLoading={isLoadingSummaries}
        error={summariesError}
      />

      {/* Filters */}
      <UsageFilters
        filters={filters}
        onFiltersChange={handleFiltersChange}
        isLoading={isLoadingSummaries}
      />

      {/* Usage Records */}
      <UsageRecords
        filters={filters}
        onRefresh={refreshData}
        onExport={handleExport}
        isExporting={isExporting}
      />
    </div>
  );
}
