import { useState, useCallback, useEffect } from 'react';
import { useUserUsageRecords } from '../../hooks/api/usage';
import type { components } from '../../generated/api';

type UsageQuery = components['schemas']['UsageRecordsQuery'];
import {
  Clock,
  Zap,
  DollarSign,
  CheckCircle,
  XCircle,
  ChevronLeft,
  ChevronRight,
  AlertCircle,
  Activity,
  Eye,
  EyeOff,
  RefreshCw,
  Download,
} from 'lucide-react';

interface UsageRecordsProps {
  filters: UsageQuery;
  onRefresh?: () => void;
  onExport?: () => void;
  isExporting?: boolean;
}

export function UsageRecords({
  filters,
  onRefresh,
  onExport,
  isExporting = false,
}: UsageRecordsProps) {
  const [currentPage, setCurrentPage] = useState(1);
  const [showDetails, setShowDetails] = useState<Set<number>>(new Set());
  const [expandedErrors, setExpandedErrors] = useState<Set<number>>(new Set());

  const pageSize = filters.limit || 50;

  // Use React Query hook for fetching usage records
  const {
    data: recordsData,
    isLoading,
    error: queryError,
    refetch,
  } = useUserUsageRecords({
    ...filters,
    offset: (currentPage - 1) * pageSize,
    limit: pageSize,
  });

  const records = recordsData?.records || [];
  const totalCount = recordsData?.total || 0;
  const error = queryError instanceof Error ? queryError.message : null;

  // Handle page changes
  const handlePageChange = (page: number) => {
    setCurrentPage(page);
  };

  // Handle refresh
  const handleRefresh = useCallback(() => {
    refetch();
    onRefresh?.();
  }, [refetch, onRefresh]);

  // Reset to first page when filters change
  useEffect(() => {
    setCurrentPage(1);
  }, [filters.start_date, filters.end_date, filters.model, filters.success_only]);

  const toggleDetails = (recordId: number) => {
    const newShowDetails = new Set(showDetails);
    if (newShowDetails.has(recordId)) {
      newShowDetails.delete(recordId);
    } else {
      newShowDetails.add(recordId);
    }
    setShowDetails(newShowDetails);
  };

  const toggleErrorExpansion = (recordId: number) => {
    const newExpandedErrors = new Set(expandedErrors);
    if (newExpandedErrors.has(recordId)) {
      newExpandedErrors.delete(recordId);
    } else {
      newExpandedErrors.add(recordId);
    }
    setExpandedErrors(newExpandedErrors);
  };

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      timeZone: 'UTC',
      timeZoneName: 'short',
    });
  };

  const formatCurrency = (costUsd?: string | null) => {
    if (costUsd === undefined || costUsd === null) return 'N/A';
    const cost = parseFloat(costUsd);
    if (isNaN(cost)) return 'N/A';
    return cost.toFixed(4); // Remove $ sign since icon already shows it
  };

  const getStatusIcon = (success: boolean) => {
    return success ? (
      <CheckCircle size={16} style={{ color: '#059669' }} />
    ) : (
      <XCircle size={16} style={{ color: '#dc2626' }} />
    );
  };

  const getStatusColor = (success: boolean) => {
    return success ? '#059669' : '#dc2626';
  };

  const truncateError = (error: string, recordId: number) => {
    const isExpanded = expandedErrors.has(recordId);
    if (error.length <= 100 || isExpanded) {
      return error;
    }
    return error.substring(0, 100) + '...';
  };

  const totalPages = Math.ceil(totalCount / pageSize);

  if (isLoading) {
    return (
      <div
        style={{
          background: 'white',
          borderRadius: '12px',
          padding: '2rem',
          textAlign: 'center',
          border: '1px solid #e9ecef',
        }}
      >
        <Activity size={32} className="loading-spinner" style={{ margin: '0 auto 1rem' }} />
        <p style={{ color: '#6c757d' }}>Loading usage records...</p>
      </div>
    );
  }

  if (error) {
    return (
      <div
        style={{
          background: '#f8d7da',
          border: '1px solid #f5c6cb',
          borderRadius: '12px',
          padding: '1.5rem',
          display: 'flex',
          alignItems: 'center',
          gap: '0.5rem',
        }}
      >
        <AlertCircle size={20} style={{ color: '#721c24' }} />
        <span style={{ color: '#721c24' }}>Failed to load usage records: {error}</span>
      </div>
    );
  }

  if (records.length === 0) {
    return (
      <div
        style={{
          background: 'white',
          borderRadius: '12px',
          padding: '3rem',
          textAlign: 'center',
          border: '2px dashed #e9ecef',
        }}
      >
        <Activity size={48} style={{ margin: '0 auto 1rem', opacity: 0.5, color: '#6c757d' }} />
        <h3 style={{ margin: '0 0 0.5rem 0', color: '#6c757d' }}>No Usage Records</h3>
        <p style={{ margin: 0, color: '#6c757d' }}>
          No usage records found for the selected filters and date range.
        </p>
      </div>
    );
  }

  return (
    <div
      style={{
        background: 'white',
        borderRadius: '12px',
        border: '1px solid #e9ecef',
        overflow: 'hidden',
      }}
    >
      {/* Header */}
      <div
        style={{
          padding: '1.5rem',
          borderBottom: '1px solid #e9ecef',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
        }}
      >
        <div>
          <h3 style={{ margin: 0, fontSize: '1.125rem', fontWeight: 600 }}>Usage Records</h3>
          <p style={{ margin: '0.25rem 0 0 0', fontSize: '0.875rem', color: '#6c757d' }}>
            {totalCount > 0
              ? `Showing ${records.length} of ${totalCount.toLocaleString()} records`
              : `${records.length} records`}
          </p>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
          {/* Action Buttons */}
          <div style={{ display: 'flex', gap: '0.5rem' }}>
            {onRefresh && (
              <button
                onClick={handleRefresh}
                disabled={isLoading}
                style={{
                  background: 'white',
                  border: '1px solid #d1d5db',
                  borderRadius: '6px',
                  padding: '0.5rem 0.75rem',
                  fontSize: '0.875rem',
                  cursor: isLoading ? 'not-allowed' : 'pointer',
                  opacity: isLoading ? 0.5 : 1,
                  display: 'flex',
                  alignItems: 'center',
                  gap: '0.5rem',
                  color: '#374151',
                }}
              >
                <RefreshCw size={16} className={isLoading ? 'loading-spinner' : ''} />
                Refresh
              </button>
            )}
            {onExport && (
              <button
                onClick={onExport}
                disabled={isExporting || isLoading}
                style={{
                  background: '#059669',
                  color: 'white',
                  border: '1px solid #059669',
                  borderRadius: '6px',
                  padding: '0.5rem 0.75rem',
                  fontSize: '0.875rem',
                  cursor: isExporting || isLoading ? 'not-allowed' : 'pointer',
                  opacity: isExporting || isLoading ? 0.5 : 1,
                  display: 'flex',
                  alignItems: 'center',
                  gap: '0.5rem',
                }}
              >
                <Download size={16} />
                {isExporting ? 'Exporting...' : 'Export CSV'}
              </button>
            )}
          </div>

          {/* Top Pagination */}
          {totalPages > 1 && (
            <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
              <div style={{ fontSize: '0.875rem', color: '#6c757d' }}>
                Page {currentPage} of {totalPages}
              </div>
              <div style={{ display: 'flex', gap: '0.5rem' }}>
                <button
                  onClick={() => handlePageChange(currentPage - 1)}
                  disabled={currentPage <= 1 || isLoading}
                  style={{
                    background: 'white',
                    border: '1px solid #d1d5db',
                    borderRadius: '6px',
                    padding: '0.5rem',
                    cursor: currentPage <= 1 || isLoading ? 'not-allowed' : 'pointer',
                    opacity: currentPage <= 1 || isLoading ? 0.5 : 1,
                    display: 'flex',
                    alignItems: 'center',
                  }}
                >
                  <ChevronLeft size={16} />
                </button>
                <button
                  onClick={() => handlePageChange(currentPage + 1)}
                  disabled={currentPage >= totalPages || isLoading}
                  style={{
                    background: 'white',
                    border: '1px solid #d1d5db',
                    borderRadius: '6px',
                    padding: '0.5rem',
                    cursor: currentPage >= totalPages || isLoading ? 'not-allowed' : 'pointer',
                    opacity: currentPage >= totalPages || isLoading ? 0.5 : 1,
                    display: 'flex',
                    alignItems: 'center',
                  }}
                >
                  <ChevronRight size={16} />
                </button>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Records List */}
      <div style={{ padding: '0', position: 'relative' }}>
        {/* Pagination Loading Overlay */}
        {isLoading && (
          <div
            style={{
              position: 'absolute',
              top: 0,
              left: 0,
              right: 0,
              bottom: 0,
              background: 'rgba(255, 255, 255, 0.8)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              zIndex: 10,
              backdropFilter: 'blur(1px)',
            }}
          >
            <Activity size={24} className="loading-spinner" style={{ color: '#3b82f6' }} />
          </div>
        )}

        {records.map((record, index) => {
          const isDetailsVisible = showDetails.has(record.id);
          const isLastItem = index === records.length - 1;

          return (
            <div
              key={record.id}
              style={{
                borderBottom: isLastItem ? 'none' : '1px solid #f1f3f4',
                transition: 'background-color 0.2s ease',
              }}
            >
              {/* Main Record Row */}
              <div
                style={{
                  padding: '1rem 1.5rem',
                  display: 'grid',
                  gridTemplateColumns: '1fr auto auto auto auto auto',
                  gap: '1rem',
                  alignItems: 'center',
                  cursor: 'pointer',
                }}
                onClick={() => toggleDetails(record.id)}
                onMouseEnter={(e) => {
                  e.currentTarget.style.backgroundColor = '#f8f9fa';
                }}
                onMouseLeave={(e) => {
                  e.currentTarget.style.backgroundColor = 'white';
                }}
              >
                {/* Model & Status */}
                <div style={{ minWidth: 0 }}>
                  <div
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      gap: '0.5rem',
                      marginBottom: '0.25rem',
                    }}
                  >
                    {getStatusIcon(record.success)}
                    <span
                      style={{
                        fontWeight: 500,
                        fontSize: '0.875rem',
                        color: getStatusColor(record.success),
                      }}
                    >
                      {record.success ? 'Success' : 'Failed'}
                    </span>
                  </div>
                  <div
                    style={{
                      fontSize: '0.875rem',
                      color: '#6c757d',
                      fontFamily: 'monospace',
                      overflow: 'hidden',
                      textOverflow: 'ellipsis',
                      whiteSpace: 'nowrap',
                    }}
                  >
                    {record.model_id}
                  </div>
                </div>

                {/* Tokens */}
                <div style={{ textAlign: 'right' }}>
                  <div
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'flex-end',
                      gap: '0.25rem',
                      marginBottom: '0.25rem',
                    }}
                  >
                    <Zap size={14} style={{ color: '#ea580c' }} />
                    <span style={{ fontSize: '0.875rem', fontWeight: 500 }}>
                      {record.total_tokens.toLocaleString()}
                    </span>
                  </div>
                  <div style={{ fontSize: '0.75rem', color: '#6c757d' }}>
                    <div>
                      ↑ {record.input_tokens.toLocaleString()} ↓{' '}
                      {record.output_tokens.toLocaleString()}
                    </div>
                    {((record.cache_read_tokens ?? 0) > 0 ||
                      (record.cache_write_tokens ?? 0) > 0) && (
                      <div style={{ fontSize: '0.7rem', opacity: 0.8 }}>
                        {(record.cache_read_tokens ?? 0) > 0 &&
                          `📖 ${record.cache_read_tokens!.toLocaleString()}`}
                        {(record.cache_read_tokens ?? 0) > 0 &&
                          (record.cache_write_tokens ?? 0) > 0 &&
                          ' '}
                        {(record.cache_write_tokens ?? 0) > 0 &&
                          `✏️ ${record.cache_write_tokens!.toLocaleString()}`}
                      </div>
                    )}
                  </div>
                </div>

                {/* Cost */}
                <div style={{ textAlign: 'right' }}>
                  <div
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'flex-end',
                      gap: '0.25rem',
                    }}
                  >
                    <DollarSign size={14} style={{ color: '#16a34a' }} />
                    <span style={{ fontSize: '0.875rem', fontWeight: 500 }}>
                      {formatCurrency(record.cost_usd)}
                    </span>
                  </div>
                </div>

                {/* Duration */}
                <div style={{ textAlign: 'right' }}>
                  <div
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'flex-end',
                      gap: '0.25rem',
                    }}
                  >
                    <Clock size={14} style={{ color: '#7c3aed' }} />
                    <span style={{ fontSize: '0.875rem' }}>
                      {record.response_time_ms ? `${record.response_time_ms}ms` : 'N/A'}
                    </span>
                  </div>
                </div>

                {/* Timestamp */}
                <div style={{ textAlign: 'right', fontSize: '0.75rem', color: '#6c757d' }}>
                  {formatDate(record.request_time)}
                </div>

                {/* Toggle Button */}
                <div>
                  <button
                    style={{
                      background: 'none',
                      border: 'none',
                      cursor: 'pointer',
                      padding: '0.25rem',
                      borderRadius: '4px',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                    }}
                  >
                    {isDetailsVisible ? (
                      <EyeOff size={16} style={{ color: '#6c757d' }} />
                    ) : (
                      <Eye size={16} style={{ color: '#6c757d' }} />
                    )}
                  </button>
                </div>
              </div>

              {/* Detailed View */}
              {isDetailsVisible && (
                <div
                  style={{
                    padding: '1rem 1.5rem',
                    background: '#f8f9fa',
                    borderTop: '1px solid #e9ecef',
                    fontSize: '0.875rem',
                  }}
                >
                  <div
                    style={{
                      display: 'grid',
                      gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
                      gap: '1rem',
                      marginBottom: record.error_message ? '1rem' : 0,
                    }}
                  >
                    <div>
                      <strong style={{ color: '#374151' }}>Request ID:</strong>
                      <div style={{ fontFamily: 'monospace', color: '#6c757d' }}>{record.id}</div>
                    </div>
                    <div>
                      <strong style={{ color: '#374151' }}>User ID:</strong>
                      <div style={{ color: '#6c757d' }}>{record.user_id}</div>
                    </div>
                    <div>
                      <strong style={{ color: '#374151' }}>Request Time:</strong>
                      <div style={{ color: '#6c757d' }}>{formatDate(record.request_time)}</div>
                    </div>
                    <div>
                      <strong style={{ color: '#374151' }}>Response Time:</strong>
                      <div style={{ color: '#6c757d' }}>
                        {record.response_time_ms ? `${record.response_time_ms}ms` : 'N/A'}
                      </div>
                    </div>
                    <div>
                      <strong style={{ color: '#374151' }}>Token Breakdown:</strong>
                      <div style={{ color: '#6c757d', fontSize: '0.8125rem' }}>
                        Input: {record.input_tokens.toLocaleString()}
                        <br />
                        Output: {record.output_tokens.toLocaleString()}
                        {(record.cache_read_tokens ?? 0) > 0 && (
                          <>
                            <br />
                            Cache Read: {record.cache_read_tokens!.toLocaleString()}
                          </>
                        )}
                        {(record.cache_write_tokens ?? 0) > 0 && (
                          <>
                            <br />
                            Cache Write: {record.cache_write_tokens!.toLocaleString()}
                          </>
                        )}
                      </div>
                    </div>
                    <div>
                      <strong style={{ color: '#374151' }}>Region & Endpoint:</strong>
                      <div style={{ color: '#6c757d', fontSize: '0.8125rem' }}>
                        {record.region} • {record.endpoint_type}
                      </div>
                    </div>
                  </div>

                  {/* Error Message */}
                  {record.error_message && (
                    <div
                      style={{
                        background: '#fef2f2',
                        border: '1px solid #fecaca',
                        borderRadius: '6px',
                        padding: '0.75rem',
                      }}
                    >
                      <div
                        style={{
                          display: 'flex',
                          alignItems: 'center',
                          justifyContent: 'space-between',
                          marginBottom: '0.5rem',
                        }}
                      >
                        <strong style={{ color: '#dc2626' }}>Error Message:</strong>
                        {record.error_message.length > 100 && (
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              toggleErrorExpansion(record.id);
                            }}
                            style={{
                              background: 'none',
                              border: 'none',
                              color: '#dc2626',
                              cursor: 'pointer',
                              fontSize: '0.75rem',
                              textDecoration: 'underline',
                            }}
                          >
                            {expandedErrors.has(record.id) ? 'Show less' : 'Show more'}
                          </button>
                        )}
                      </div>
                      <div
                        style={{
                          color: '#991b1b',
                          fontFamily: 'monospace',
                          fontSize: '0.8125rem',
                          lineHeight: 1.4,
                          whiteSpace: 'pre-wrap',
                        }}
                      >
                        {truncateError(record.error_message, record.id)}
                      </div>
                    </div>
                  )}

                  {/* Stop Reason */}
                  {record.stop_reason && (
                    <div
                      style={{
                        background: '#f0f9ff',
                        border: '1px solid #bae6fd',
                        borderRadius: '6px',
                        padding: '0.75rem',
                        marginTop: record.error_message ? '0.75rem' : 0,
                      }}
                    >
                      <div
                        style={{
                          display: 'flex',
                          alignItems: 'center',
                          gap: '0.5rem',
                        }}
                      >
                        <strong style={{ color: '#0369a1' }}>Stop Reason:</strong>
                        <span
                          style={{
                            color: '#0c4a6e',
                            fontSize: '0.875rem',
                            fontFamily: 'monospace',
                            background: '#e0f2fe',
                            padding: '0.125rem 0.375rem',
                            borderRadius: '3px',
                          }}
                        >
                          {record.stop_reason}
                        </span>
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>
          );
        })}
      </div>

      {/* Pagination */}
      {totalPages > 1 && (
        <div
          style={{
            padding: '1rem 1.5rem',
            borderTop: '1px solid #e9ecef',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'between',
          }}
        >
          <div style={{ fontSize: '0.875rem', color: '#6c757d' }}>
            Page {currentPage} of {totalPages}
          </div>
          <div style={{ display: 'flex', gap: '0.5rem' }}>
            <button
              onClick={() => handlePageChange(currentPage - 1)}
              disabled={currentPage <= 1 || isLoading}
              style={{
                background: 'white',
                border: '1px solid #d1d5db',
                borderRadius: '6px',
                padding: '0.5rem',
                cursor: currentPage <= 1 || isLoading ? 'not-allowed' : 'pointer',
                opacity: currentPage <= 1 || isLoading ? 0.5 : 1,
                display: 'flex',
                alignItems: 'center',
              }}
            >
              <ChevronLeft size={16} />
            </button>
            <button
              onClick={() => handlePageChange(currentPage + 1)}
              disabled={currentPage >= totalPages || isLoading}
              style={{
                background: 'white',
                border: '1px solid #d1d5db',
                borderRadius: '6px',
                padding: '0.5rem',
                cursor: currentPage >= totalPages || isLoading ? 'not-allowed' : 'pointer',
                opacity: currentPage >= totalPages || isLoading ? 0.5 : 1,
                display: 'flex',
                alignItems: 'center',
              }}
            >
              <ChevronRight size={16} />
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
