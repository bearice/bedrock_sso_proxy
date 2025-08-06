import { useState, useCallback, useEffect } from 'react';
import type { components } from '../../generated/api';

type UsageQuery = components['schemas']['UsageRecordsQuery'];
import { Calendar, Filter, RotateCcw, Search, Check } from 'lucide-react';

interface UsageFiltersProps {
  filters: UsageQuery;
  onFiltersChange: (filters: UsageQuery) => void;
  availableModels?: string[];
  isLoading?: boolean;
}

export function UsageFilters({
  filters,
  onFiltersChange,
  availableModels = [],
  isLoading = false,
}: UsageFiltersProps) {
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [draftFilters, setDraftFilters] = useState<UsageQuery>(filters);
  const [hasChanges, setHasChanges] = useState(false);

  // Convert ISO date to YYYY-MM-DD for date inputs
  const formatDateForInput = (isoDate?: string | null): string => {
    if (!isoDate) return '';
    return isoDate.split('T')[0];
  };

  // Convert YYYY-MM-DD to ISO string for API
  const formatDateForApi = (dateString: string): string => {
    if (!dateString) return '';
    // Add time component for full ISO string
    return new Date(dateString + 'T00:00:00.000Z').toISOString();
  };

  // Check if draft filters differ from current filters
  const filtersEqual = useCallback((a: UsageQuery, b: UsageQuery): boolean => {
    const keys = ['start_date', 'end_date', 'model', 'success_only'] as const;
    return keys.every((key) => a[key] === b[key]);
  }, []);

  // Apply draft filters
  const applyFilters = useCallback(() => {
    onFiltersChange({
      ...draftFilters,
      offset: 0, // Reset to first page when filters change
    });
    setHasChanges(false);
  }, [draftFilters, onFiltersChange]);

  // Discard draft changes
  const discardChanges = useCallback(() => {
    setDraftFilters(filters);
    setHasChanges(false);
  }, [filters]);

  // Update draft filters when filters prop changes (e.g., reset)
  useEffect(() => {
    setDraftFilters(filters);
    setHasChanges(false);
  }, [filters]);

  // Handle keyboard shortcuts
  useEffect(() => {
    const handleKeyDown = (event: KeyboardEvent) => {
      if (!hasChanges) return;

      if (event.key === 'Enter' && (event.ctrlKey || event.metaKey)) {
        event.preventDefault();
        applyFilters();
      } else if (event.key === 'Escape') {
        event.preventDefault();
        discardChanges();
      }
    };

    document.addEventListener('keydown', handleKeyDown);
    return () => document.removeEventListener('keydown', handleKeyDown);
  }, [hasChanges, applyFilters, discardChanges]);

  const handleInputChange = useCallback(
    (field: keyof UsageQuery, value: string | number | boolean | undefined) => {
      let processedValue = value;

      // Convert date strings to ISO format for API
      if ((field === 'start_date' || field === 'end_date') && typeof value === 'string') {
        processedValue = formatDateForApi(value);
      }

      const newDraftFilters = {
        ...draftFilters,
        [field]: processedValue || undefined,
      };

      setDraftFilters(newDraftFilters);
      setHasChanges(!filtersEqual(newDraftFilters, filters));
    },
    [draftFilters, filters, filtersEqual]
  );

  const getThisMonthRange = useCallback(() => {
    const now = new Date();
    const startOfMonth = new Date(now.getFullYear(), now.getMonth(), 1);

    // Set end date to end of today to include all of today's data
    const endOfToday = new Date(now);
    endOfToday.setHours(23, 59, 59, 999);

    return {
      start_date: startOfMonth.toISOString(),
      end_date: endOfToday.toISOString(),
    };
  }, []);

  const resetFilters = useCallback(() => {
    const thisMonthRange = getThisMonthRange();

    const resetFilters = {
      ...thisMonthRange,
      limit: 50,
      offset: 0,
    };

    setDraftFilters(resetFilters);
    onFiltersChange(resetFilters);
    setHasChanges(false);
  }, [onFiltersChange, getThisMonthRange]);

  const getPresetRange = useCallback(
    (days: number) => {
      const now = new Date();
      const startDate = new Date(now.getTime() - days * 24 * 60 * 60 * 1000);

      // Set end date to end of today to include all of today's data
      const endOfToday = new Date(now);
      endOfToday.setHours(23, 59, 59, 999);

      const newFilters = {
        ...draftFilters,
        start_date: startDate.toISOString(),
        end_date: endOfToday.toISOString(),
        offset: 0, // Reset to first page when date range changes
      };

      // Apply immediately - no need to wait for user confirmation on preset ranges
      setDraftFilters(newFilters);
      onFiltersChange(newFilters);
      setHasChanges(false);
    },
    [draftFilters, onFiltersChange]
  );

  return (
    <div
      style={{
        background: 'white',
        borderRadius: '12px',
        padding: '1.5rem',
        marginBottom: '1.5rem',
        border: '1px solid #e9ecef',
        boxShadow: '0 2px 4px rgba(0, 0, 0, 0.05)',
      }}
    >
      {/* Header */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          marginBottom: '1.5rem',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <Filter size={20} style={{ color: '#4f46e5' }} />
          <h3 style={{ margin: 0, fontSize: '1.125rem', fontWeight: 600 }}>Usage Filters</h3>
          {hasChanges && (
            <span
              style={{
                fontSize: '0.75rem',
                background: '#fbbf24',
                color: '#92400e',
                padding: '0.25rem 0.5rem',
                borderRadius: '12px',
                fontWeight: 500,
              }}
              title="You have unsaved filter changes. Press Ctrl+Enter to apply or Escape to discard."
            >
              Pending Changes
            </span>
          )}
        </div>
        <div style={{ display: 'flex', gap: '0.5rem' }}>
          {hasChanges && (
            <>
              <button
                onClick={applyFilters}
                disabled={isLoading}
                style={{
                  background: '#059669',
                  color: 'white',
                  border: '1px solid #059669',
                  borderRadius: '6px',
                  padding: '0.5rem 0.75rem',
                  fontSize: '0.875rem',
                  cursor: isLoading ? 'not-allowed' : 'pointer',
                  opacity: isLoading ? 0.5 : 1,
                  display: 'flex',
                  alignItems: 'center',
                  gap: '0.25rem',
                }}
              >
                <Check size={14} />
                Apply Filters
              </button>
              <button
                onClick={discardChanges}
                disabled={isLoading}
                style={{
                  background: 'none',
                  border: '1px solid #d1d5db',
                  borderRadius: '6px',
                  padding: '0.5rem 0.75rem',
                  fontSize: '0.875rem',
                  cursor: isLoading ? 'not-allowed' : 'pointer',
                  color: '#6b7280',
                  opacity: isLoading ? 0.5 : 1,
                }}
              >
                Discard
              </button>
            </>
          )}
          <button
            onClick={() => setShowAdvanced(!showAdvanced)}
            style={{
              background: 'none',
              border: '1px solid #d1d5db',
              borderRadius: '6px',
              padding: '0.5rem 0.75rem',
              fontSize: '0.875rem',
              cursor: 'pointer',
              color: '#6b7280',
            }}
          >
            {showAdvanced ? 'Hide' : 'Show'} Advanced
          </button>
          <button
            onClick={resetFilters}
            disabled={isLoading}
            style={{
              background: 'none',
              border: '1px solid #d1d5db',
              borderRadius: '6px',
              padding: '0.5rem 0.75rem',
              fontSize: '0.875rem',
              cursor: isLoading ? 'not-allowed' : 'pointer',
              color: '#6b7280',
              opacity: isLoading ? 0.5 : 1,
              display: 'flex',
              alignItems: 'center',
              gap: '0.25rem',
            }}
          >
            <RotateCcw size={14} />
            Reset
          </button>
        </div>
      </div>

      {/* Date Range */}
      <div style={{ marginBottom: '1.5rem' }}>
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '0.5rem',
            marginBottom: '0.75rem',
          }}
        >
          <Calendar size={16} style={{ color: '#6b7280' }} />
          <label
            style={{
              fontSize: '0.875rem',
              fontWeight: 500,
              color: '#374151',
            }}
          >
            Date Range
          </label>
        </div>

        <div
          style={{
            display: 'grid',
            gridTemplateColumns: '1fr 1fr',
            gap: '0.75rem',
            marginBottom: '0.75rem',
          }}
        >
          <div>
            <label
              htmlFor="start-date"
              style={{
                display: 'block',
                fontSize: '0.75rem',
                color: '#6b7280',
                marginBottom: '0.25rem',
              }}
            >
              Start Date
            </label>
            <input
              id="start-date"
              type="date"
              value={formatDateForInput(draftFilters.start_date)}
              onChange={(e) => handleInputChange('start_date', e.target.value)}
              disabled={isLoading}
              style={{
                width: '100%',
                padding: '0.5rem',
                border: '1px solid #d1d5db',
                borderRadius: '6px',
                fontSize: '0.875rem',
                backgroundColor: isLoading ? '#f9fafb' : 'white',
                opacity: isLoading ? 0.7 : 1,
              }}
            />
          </div>
          <div>
            <label
              htmlFor="end-date"
              style={{
                display: 'block',
                fontSize: '0.75rem',
                color: '#6b7280',
                marginBottom: '0.25rem',
              }}
            >
              End Date
            </label>
            <input
              id="end-date"
              type="date"
              value={formatDateForInput(draftFilters.end_date)}
              onChange={(e) => handleInputChange('end_date', e.target.value)}
              disabled={isLoading}
              style={{
                width: '100%',
                padding: '0.5rem',
                border: '1px solid #d1d5db',
                borderRadius: '6px',
                fontSize: '0.875rem',
                backgroundColor: isLoading ? '#f9fafb' : 'white',
                opacity: isLoading ? 0.7 : 1,
              }}
            />
          </div>
        </div>

        {/* Quick Date Presets */}
        <div
          style={{
            display: 'flex',
            gap: '0.5rem',
            flexWrap: 'wrap',
          }}
        >
          <button
            onClick={() => {
              const thisMonthRange = getThisMonthRange();
              const newFilters = {
                ...draftFilters,
                ...thisMonthRange,
                offset: 0,
              };
              setDraftFilters(newFilters);
              onFiltersChange(newFilters);
              setHasChanges(false);
            }}
            disabled={isLoading}
            style={{
              background: '#4f46e5',
              color: 'white',
              border: '1px solid #4f46e5',
              borderRadius: '6px',
              padding: '0.25rem 0.5rem',
              fontSize: '0.75rem',
              cursor: isLoading ? 'not-allowed' : 'pointer',
              fontWeight: 500,
              opacity: isLoading ? 0.5 : 1,
            }}
          >
            This Month
          </button>
          {[
            { label: 'Last 7 days', days: 7 },
            { label: 'Last 30 days', days: 30 },
            { label: 'Last 90 days', days: 90 },
          ].map((preset) => (
            <button
              key={preset.days}
              onClick={() => getPresetRange(preset.days)}
              disabled={isLoading}
              style={{
                background: 'none',
                border: '1px solid #d1d5db',
                borderRadius: '6px',
                padding: '0.25rem 0.5rem',
                fontSize: '0.75rem',
                cursor: isLoading ? 'not-allowed' : 'pointer',
                color: '#6b7280',
                opacity: isLoading ? 0.5 : 1,
              }}
            >
              {preset.label}
            </button>
          ))}
        </div>
      </div>

      {/* Advanced Filters */}
      {showAdvanced && (
        <div
          style={{
            borderTop: '1px solid #e5e7eb',
            paddingTop: '1.5rem',
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
            gap: '1rem',
          }}
        >
          {/* Model Filter */}
          <div>
            <label
              htmlFor="model-filter"
              style={{
                display: 'block',
                fontSize: '0.875rem',
                fontWeight: 500,
                color: '#374151',
                marginBottom: '0.5rem',
              }}
            >
              Model
            </label>
            <select
              id="model-filter"
              value={draftFilters.model || ''}
              onChange={(e) => handleInputChange('model', e.target.value)}
              disabled={isLoading}
              style={{
                width: '100%',
                padding: '0.5rem',
                border: '1px solid #d1d5db',
                borderRadius: '6px',
                fontSize: '0.875rem',
                backgroundColor: isLoading ? '#f9fafb' : 'white',
                opacity: isLoading ? 0.7 : 1,
              }}
            >
              <option value="">All Models</option>
              {availableModels.map((model) => (
                <option key={model} value={model}>
                  {model}
                </option>
              ))}
            </select>
          </div>

          {/* Success Filter */}
          <div>
            <label
              htmlFor="success-filter"
              style={{
                display: 'block',
                fontSize: '0.875rem',
                fontWeight: 500,
                color: '#374151',
                marginBottom: '0.5rem',
              }}
            >
              Status
            </label>
            <select
              id="success-filter"
              value={
                draftFilters.success_only === undefined || draftFilters.success_only === null
                  ? ''
                  : draftFilters.success_only.toString()
              }
              onChange={(e) =>
                handleInputChange(
                  'success_only',
                  e.target.value === '' ? undefined : e.target.value === 'true'
                )
              }
              disabled={isLoading}
              style={{
                width: '100%',
                padding: '0.5rem',
                border: '1px solid #d1d5db',
                borderRadius: '6px',
                fontSize: '0.875rem',
                backgroundColor: isLoading ? '#f9fafb' : 'white',
                opacity: isLoading ? 0.7 : 1,
              }}
            >
              <option value="">All Requests</option>
              <option value="true">Successful Only</option>
              <option value="false">Failed Only</option>
            </select>
          </div>

          {/* Limit */}
          <div>
            <label
              htmlFor="limit-filter"
              style={{
                display: 'block',
                fontSize: '0.875rem',
                fontWeight: 500,
                color: '#374151',
                marginBottom: '0.5rem',
              }}
            >
              Results per page
            </label>
            <select
              id="limit-filter"
              value={draftFilters.limit || 50}
              onChange={(e) => handleInputChange('limit', parseInt(e.target.value))}
              disabled={isLoading}
              style={{
                width: '100%',
                padding: '0.5rem',
                border: '1px solid #d1d5db',
                borderRadius: '6px',
                fontSize: '0.875rem',
                backgroundColor: isLoading ? '#f9fafb' : 'white',
                opacity: isLoading ? 0.7 : 1,
              }}
            >
              <option value="10">10</option>
              <option value="25">25</option>
              <option value="50">50</option>
              <option value="100">100</option>
            </select>
          </div>
        </div>
      )}

      {/* Active Filters Summary */}
      {(draftFilters.model || draftFilters.success_only !== undefined) && (
        <div
          style={{
            marginTop: '1rem',
            padding: '0.75rem',
            background: '#f0f9ff',
            border: '1px solid #0ea5e9',
            borderRadius: '6px',
            fontSize: '0.875rem',
          }}
        >
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '0.5rem',
              marginBottom: '0.5rem',
            }}
          >
            <Search size={14} style={{ color: '#0ea5e9' }} />
            <span style={{ fontWeight: 500, color: '#075985' }}>Active Filters:</span>
          </div>
          <div style={{ color: '#0c4a6e', lineHeight: 1.4 }}>
            {draftFilters.model && <div>• Model: {draftFilters.model}</div>}
            {draftFilters.success_only !== undefined && (
              <div>
                • Status: {draftFilters.success_only ? 'Successful' : 'Failed'} requests only
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
