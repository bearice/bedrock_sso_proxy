import { useState, useEffect, useCallback } from 'react';
import { useAuth } from '../../hooks/useAuth';
import { usageApi, ApiError } from '../../services/api';
import { UsageStats as UsageStatsType, UsageQuery, UsageRecord } from '../../types/usage';
import { UsageStats } from './UsageStats';
import { UsageFilters } from './UsageFilters';
import { UsageRecords } from './UsageRecords';
import { Activity, RefreshCw, Download, AlertCircle } from 'lucide-react';

export function UsageTracking() {
  const { token } = useAuth();
  const [stats, setStats] = useState<UsageStatsType | null>(null);
  const [records, setRecords] = useState<UsageRecord[]>([]);
  const [totalCount, setTotalCount] = useState(0);
  const [availableModels, setAvailableModels] = useState<string[]>([]);

  const [isLoadingStats, setIsLoadingStats] = useState(true);
  const [isLoadingRecords, setIsLoadingRecords] = useState(true);
  const [isLoadingModels, setIsLoadingModels] = useState(true);
  const [isExporting, setIsExporting] = useState(false);

  const [statsError, setStatsError] = useState<string | null>(null);
  const [recordsError, setRecordsError] = useState<string | null>(null);

  // Initialize filters with last 30 days
  const getDefaultFilters = useCallback((): UsageQuery => {
    const now = new Date();
    const thirtyDaysAgo = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);

    return {
      start_date: thirtyDaysAgo.toISOString().split('T')[0],
      end_date: now.toISOString().split('T')[0],
      limit: 50,
      offset: 0,
    };
  }, []);

  const [filters, setFilters] = useState<UsageQuery>(getDefaultFilters);
  const [currentPage, setCurrentPage] = useState(1);

  // Load usage statistics
  const loadStats = useCallback(async () => {
    if (!token) return;

    try {
      setIsLoadingStats(true);
      setStatsError(null);

      const statsQuery = {
        start_date: filters.start_date,
        end_date: filters.end_date,
        model: filters.model,
        success: filters.success_only,
      };

      const statsData = await usageApi.getUsageStats(token, statsQuery);
      setStats(statsData);
    } catch (err) {
      console.error('Failed to load usage stats:', err);
      setStatsError(err instanceof ApiError ? err.message : 'Failed to load usage statistics');
    } finally {
      setIsLoadingStats(false);
    }
  }, [token, filters.start_date, filters.end_date, filters.model, filters.success_only]);

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

  // Load available models
  const loadModels = useCallback(async () => {
    if (!token) return;

    try {
      setIsLoadingModels(true);

      const models = await usageApi.getAvailableModels(token);
      setAvailableModels(models);
    } catch (err) {
      console.error('Failed to load available models:', err);
      // Models error is non-critical, so we don't display it to user
    } finally {
      setIsLoadingModels(false);
    }
  }, [token]);

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
    loadStats();
    loadRecords();
    loadModels();
  }, [loadStats, loadRecords, loadModels]);

  // Initial data load
  useEffect(() => {
    if (token) {
      loadStats();
      loadRecords();
      loadModels();
    }
  }, [token, loadStats, loadRecords, loadModels]);

  // Reload when filters change (but not on initial load)
  useEffect(() => {
    if (token) {
      loadStats();
      loadRecords();
    }
  }, [filters, loadStats, loadRecords, token]);

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
          <p style={{ margin: '0.5rem 0 0 0', color: '#6c757d' }}>
            Monitor your API usage, token consumption, and costs
          </p>
        </div>
        <div style={{ display: 'flex', gap: '0.75rem' }}>
          <button
            onClick={refreshData}
            disabled={isLoadingStats || isLoadingRecords}
            className="btn btn-secondary"
            style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}
          >
            <RefreshCw
              size={16}
              className={isLoadingStats || isLoadingRecords ? 'loading-spinner' : ''}
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

      {/* Usage Statistics */}
      <UsageStats stats={stats} isLoading={isLoadingStats} error={statsError} />

      {/* Filters */}
      <UsageFilters
        filters={filters}
        onFiltersChange={handleFiltersChange}
        availableModels={availableModels}
        isLoading={isLoadingRecords}
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
      {false && (
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
              <strong>Available Models:</strong> {availableModels.length} models loaded
            </div>
            <div>
              <strong>Loading States:</strong> Stats: {isLoadingStats.toString()}, Records:{' '}
              {isLoadingRecords.toString()}, Models: {isLoadingModels.toString()}
            </div>
            <div>
              <strong>Records Count:</strong> {records.length} loaded, {totalCount} total
            </div>
          </div>
        </details>
      )}
    </div>
  );
}
