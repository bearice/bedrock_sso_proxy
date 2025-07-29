import { useState } from 'react';
import { UsageRecord } from '../../types/usage';
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
} from 'lucide-react';

interface UsageRecordsProps {
  records: UsageRecord[];
  isLoading: boolean;
  error: string | null;
  totalCount?: number;
  currentPage: number;
  pageSize: number;
  onPageChange: (page: number) => void;
}

export function UsageRecords({
  records,
  isLoading,
  error,
  totalCount = 0,
  currentPage,
  pageSize,
  onPageChange,
}: UsageRecordsProps) {
  const [showDetails, setShowDetails] = useState<Set<number>>(new Set());
  const [expandedErrors, setExpandedErrors] = useState<Set<number>>(new Set());

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
    });
  };

  const formatDuration = (startTime: string, endTime?: string) => {
    if (!endTime) return 'N/A';
    const start = new Date(startTime).getTime();
    const end = new Date(endTime).getTime();
    const duration = end - start;

    if (duration < 1000) {
      return `${duration}ms`;
    } else if (duration < 60000) {
      return `${(duration / 1000).toFixed(1)}s`;
    } else {
      return `${(duration / 60000).toFixed(1)}m`;
    }
  };

  const formatCurrency = (cents?: number) => {
    if (cents === undefined || cents === null) return 'N/A';
    return `$${(cents / 100).toFixed(4)}`;
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
      </div>

      {/* Records List */}
      <div style={{ padding: '0' }}>
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
                    {record.input_tokens.toLocaleString()} + {record.output_tokens.toLocaleString()}
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
                      {formatCurrency(record.cost_cents)}
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
                      {formatDuration(record.request_timestamp, record.response_timestamp)}
                    </span>
                  </div>
                </div>

                {/* Timestamp */}
                <div style={{ textAlign: 'right', fontSize: '0.75rem', color: '#6c757d' }}>
                  {formatDate(record.request_timestamp)}
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
                      <div style={{ color: '#6c757d' }}>{formatDate(record.request_timestamp)}</div>
                    </div>
                    {record.response_timestamp && (
                      <div>
                        <strong style={{ color: '#374151' }}>Response Time:</strong>
                        <div style={{ color: '#6c757d' }}>
                          {formatDate(record.response_timestamp)}
                        </div>
                      </div>
                    )}
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
              onClick={() => onPageChange(currentPage - 1)}
              disabled={currentPage <= 1}
              style={{
                background: 'white',
                border: '1px solid #d1d5db',
                borderRadius: '6px',
                padding: '0.5rem',
                cursor: currentPage <= 1 ? 'not-allowed' : 'pointer',
                opacity: currentPage <= 1 ? 0.5 : 1,
                display: 'flex',
                alignItems: 'center',
              }}
            >
              <ChevronLeft size={16} />
            </button>
            <button
              onClick={() => onPageChange(currentPage + 1)}
              disabled={currentPage >= totalPages}
              style={{
                background: 'white',
                border: '1px solid #d1d5db',
                borderRadius: '6px',
                padding: '0.5rem',
                cursor: currentPage >= totalPages ? 'not-allowed' : 'pointer',
                opacity: currentPage >= totalPages ? 0.5 : 1,
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
