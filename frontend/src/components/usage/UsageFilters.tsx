import { useState, useCallback } from 'react';
import { UsageQuery } from '../../types/usage';
import { Calendar, Filter, RotateCcw, Search } from 'lucide-react';

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

  const handleInputChange = useCallback(
    (field: keyof UsageQuery, value: string | number | boolean | undefined) => {
      onFiltersChange({
        ...filters,
        [field]: value || undefined,
      });
    },
    [filters, onFiltersChange]
  );

  const resetFilters = useCallback(() => {
    const now = new Date();
    const thirtyDaysAgo = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);

    onFiltersChange({
      start_date: thirtyDaysAgo.toISOString().split('T')[0],
      end_date: now.toISOString().split('T')[0],
      limit: 50,
      offset: 0,
    });
  }, [onFiltersChange]);

  const getPresetRange = useCallback(
    (days: number) => {
      const now = new Date();
      const startDate = new Date(now.getTime() - days * 24 * 60 * 60 * 1000);

      onFiltersChange({
        ...filters,
        start_date: startDate.toISOString().split('T')[0],
        end_date: now.toISOString().split('T')[0],
      });
    },
    [filters, onFiltersChange]
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
        </div>
        <div style={{ display: 'flex', gap: '0.5rem' }}>
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
              value={filters.start_date || ''}
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
              value={filters.end_date || ''}
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
              value={filters.model || ''}
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
              value={filters.success_only === undefined ? '' : filters.success_only.toString()}
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
              value={filters.limit || 50}
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

          {/* Min/Max Tokens */}
          <div>
            <label
              htmlFor="min-tokens"
              style={{
                display: 'block',
                fontSize: '0.875rem',
                fontWeight: 500,
                color: '#374151',
                marginBottom: '0.5rem',
              }}
            >
              Min Tokens
            </label>
            <input
              id="min-tokens"
              type="number"
              min="0"
              value={filters.min_tokens || ''}
              onChange={(e) =>
                handleInputChange(
                  'min_tokens',
                  e.target.value ? parseInt(e.target.value) : undefined
                )
              }
              placeholder="No minimum"
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
              htmlFor="max-tokens"
              style={{
                display: 'block',
                fontSize: '0.875rem',
                fontWeight: 500,
                color: '#374151',
                marginBottom: '0.5rem',
              }}
            >
              Max Tokens
            </label>
            <input
              id="max-tokens"
              type="number"
              min="0"
              value={filters.max_tokens || ''}
              onChange={(e) =>
                handleInputChange(
                  'max_tokens',
                  e.target.value ? parseInt(e.target.value) : undefined
                )
              }
              placeholder="No maximum"
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
      )}

      {/* Active Filters Summary */}
      {(filters.model ||
        filters.success_only !== undefined ||
        filters.min_tokens ||
        filters.max_tokens) && (
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
            {filters.model && <div>• Model: {filters.model}</div>}
            {filters.success_only !== undefined && (
              <div>• Status: {filters.success_only ? 'Successful' : 'Failed'} requests only</div>
            )}
            {filters.min_tokens && <div>• Min tokens: {filters.min_tokens.toLocaleString()}</div>}
            {filters.max_tokens && <div>• Max tokens: {filters.max_tokens.toLocaleString()}</div>}
          </div>
        </div>
      )}
    </div>
  );
}
