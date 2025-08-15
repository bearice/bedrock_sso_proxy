import { useState, useCallback } from 'react';
import { useAuth } from '../../hooks/useAuth';
import { useUserUsageSummaries } from '../../hooks/api/usage';
import type { components } from '../../generated/api';

type UsageQuery = components['schemas']['UsageRecordsQuery'];
import { UsageFilters } from './UsageFilters';
import { UsageRecords } from './UsageRecords';
import { UsageSummaryCharts } from './UsageSummaryCharts';
import { Activity, AlertCircle } from 'lucide-react';

export function UsageTracking() {
  const { token } = useAuth();
  const [isExporting, setIsExporting] = useState(false);

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
      const diffMs = end.getTime() - start.getTime();
      const diffDays = diffMs / (1000 * 60 * 60 * 24);

      if (diffDays <= 2) return 'hourly';
      if (diffDays <= 31) return 'daily';
      if (diffDays <= 90) return 'weekly';
      return 'monthly';
    },
    []
  );

  // Use React Query hook for summaries
  const summariesQuery = {
    start_date: filters.start_date,
    end_date: filters.end_date,
    period_type: getOptimalPeriodType(filters.start_date!, filters.end_date!),
    model_id: filters.model,
    limit: 1000,
    offset: 0,
  };

  const {
    data: summariesData,
    isLoading: isLoadingSummaries,
    error: summariesQueryError,
    refetch: refetchSummaries,
  } = useUserUsageSummaries(summariesQuery);

  const summaries = summariesData?.summaries || [];
  const summariesError = summariesQueryError instanceof Error ? summariesQueryError.message : null;

  // Handle filter changes
  const handleFiltersChange = useCallback((newFilters: UsageQuery) => {
    setFilters(newFilters);
  }, []);

  // Refresh all data
  const refreshData = useCallback(() => {
    refetchSummaries();
  }, [refetchSummaries]);

  // Export usage data using direct API call
  const handleExport = useCallback(async () => {
    try {
      setIsExporting(true);

      // Build query parameters
      const params = new URLSearchParams();
      if (filters.start_date) params.append('start_date', filters.start_date);
      if (filters.end_date) params.append('end_date', filters.end_date);
      if (filters.model) params.append('model', filters.model);
      if (filters.success_only !== undefined && filters.success_only !== null) {
        params.append('success_only', filters.success_only.toString());
      }
      params.append('format', 'csv');
      params.append('limit', '10000');

      const response = await fetch(`/api/usage/records?${params.toString()}`, {
        headers: {
          Authorization: `Bearer ${token}`,
        },
      });

      if (!response.ok) {
        throw new Error(`Export failed: ${response.statusText}`);
      }

      const blob = await response.blob();

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
      alert('Failed to export usage data');
    } finally {
      setIsExporting(false);
    }
  }, [token, filters]);

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
