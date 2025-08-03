import { useState, useEffect, useCallback } from 'react';
import { useAuth } from '../../hooks/useAuth';
import { usageApi, ApiError } from '../../services/api';
import { UsageQuery, UsageRecord, UsageSummary, UsageSummariesQuery } from '../../types/usage';
import { UsageFilters } from './UsageFilters';
import { UsageRecords } from './UsageRecords';
import { UsageSummaryCharts } from './UsageSummaryCharts';
import { Activity, RefreshCw, Download, AlertCircle } from 'lucide-react';

export function UsageTracking() {
  const { token } = useAuth();
  const [summaries, setSummaries] = useState<UsageSummary[]>([]);
  const [records, setRecords] = useState<UsageRecord[]>([]);
  const [totalCount, setTotalCount] = useState(0);

  const [isLoadingSummaries, setIsLoadingSummaries] = useState(true);
  const [isLoadingRecords, setIsLoadingRecords] = useState(true);
  const [isExporting, setIsExporting] = useState(false);

  const [summariesError, setSummariesError] = useState<string | null>(null);
  const [recordsError, setRecordsError] = useState<string | null>(null);

  // Initialize filters with last 30 days
  const getDefaultFilters = useCallback((): UsageQuery => {
    const now = new Date();
    const thirtyDaysAgo = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);

    return {
      start_date: thirtyDaysAgo.toISOString(),
      end_date: now.toISOString(),
      limit: 50,
      offset: 0,
    };
  }, []);

  const [filters, setFilters] = useState<UsageQuery>(getDefaultFilters);
  const [currentPage, setCurrentPage] = useState(1);

  // Load usage summaries
  const loadSummaries = useCallback(async () => {
    if (!token) return;

    try {
      setIsLoadingSummaries(true);
      setSummariesError(null);

      const summariesQuery: UsageSummariesQuery = {
        start_date: filters.start_date,
        end_date: filters.end_date,
        model_id: filters.model,
        period_type: 'daily', // Default to daily summaries
        limit: 1000, // Get more summaries for better chart data
      };

      const summariesData = await usageApi.getUsageSummaries(token, summariesQuery);
      setSummaries(summariesData.summaries);
    } catch (err) {
      console.error('Failed to load usage summaries:', err);
      setSummariesError(err instanceof ApiError ? err.message : 'Failed to load usage summaries');
    } finally {
      setIsLoadingSummaries(false);
    }
  }, [token, filters.start_date, filters.end_date, filters.model]);

  // Load usage records
  const loadRecords = useCallback(async () => {
    if (!token) return;

    try {
      setIsLoadingRecords(true);
      setRecordsError(null);

      const response = await usageApi.getUsageRecords(token, filters);
      setRecords(response.records);
      setTotalCount(response.total || response.records.length);
    } catch (err) {
      console.error('Failed to load usage records:', err);
      setRecordsError(err instanceof ApiError ? err.message : 'Failed to load usage records');
    } finally {
      setIsLoadingRecords(false);
    }
  }, [token, filters]);

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
        limit: totalCount, // Export all records that match the filter
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
  }, [token, filters.start_date, filters.end_date, filters.model, filters.success_only, totalCount]);

  // Handle filter changes
  const handleFiltersChange = useCallback((newFilters: UsageQuery) => {
    setFilters(newFilters);
    setCurrentPage(1); // Reset to first page when filters change
  }, []);

  // Handle page changes
  const handlePageChange = useCallback(
    (page: number) => {
      setCurrentPage(page);
      const newOffset = (page - 1) * (filters.limit || 50);
      setFilters((prev) => ({ ...prev, offset: newOffset }));
    },
    [filters.limit]
  );

  // Refresh all data
  const refreshData = useCallback(() => {
    loadSummaries();
    loadRecords();
  }, [loadSummaries, loadRecords]);

  // Initial data load
  useEffect(() => {
    if (token) {
      loadSummaries();
      loadRecords();
    }
  }, [token, loadSummaries, loadRecords]);

  // Reload when filters change (but not on initial load)
  useEffect(() => {
    if (token) {
      loadSummaries();
      loadRecords();
    }
  }, [filters, loadSummaries, loadRecords, token]);

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
          <button
            onClick={refreshData}
            disabled={isLoadingSummaries || isLoadingRecords}
            className="btn btn-secondary"
            style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}
          >
            <RefreshCw
              size={16}
              className={isLoadingSummaries || isLoadingRecords ? 'loading-spinner' : ''}
            />
            Refresh
          </button>
          <button
            onClick={handleExport}
            disabled={isExporting || !records.length}
            className="btn"
            style={{
              background: '#059669',
              color: 'white',
              border: '1px solid #059669',
              display: 'flex',
              alignItems: 'center',
              gap: '0.5rem',
            }}
          >
            <Download size={16} />
            {isExporting ? 'Exporting...' : 'Export CSV'}
          </button>
        </div>
      </div>

      {/* Filters */}
      <UsageFilters
        filters={filters}
        onFiltersChange={handleFiltersChange}
        isLoading={isLoadingRecords}
      />

      {/* Usage Summary Charts */}
      <UsageSummaryCharts
        summaries={summaries}
        isLoading={isLoadingSummaries}
        error={summariesError}
      />

      {/* Usage Records */}
      <UsageRecords
        records={records}
        isLoading={isLoadingRecords}
        error={recordsError}
        totalCount={totalCount}
        currentPage={currentPage}
        pageSize={filters.limit || 50}
        onPageChange={handlePageChange}
      />

      {/* Debug Info (development only) */}
      {
        <details
          style={{
            marginTop: '2rem',
            padding: '1rem',
            background: '#f8f9fa',
            borderRadius: '8px',
            fontSize: '0.875rem',
          }}
        >
          <summary style={{ cursor: 'pointer', fontWeight: 'bold' }}>Debug Information</summary>
          <div style={{ marginTop: '0.5rem' }}>
            <div>
              <strong>Current Filters:</strong> {JSON.stringify(filters, null, 2)}
            </div>
            <div>
              <strong>Loading States:</strong> Summaries: {isLoadingSummaries.toString()}, Records:{' '}
              {isLoadingRecords.toString()}
            </div>
            <div>
              <strong>Records Count:</strong> {records.length} loaded, {totalCount} total
            </div>
          </div>
        </details>
      }
    </div>
  );
}
