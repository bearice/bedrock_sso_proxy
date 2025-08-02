import { UsageStats as UsageStatsType } from '../../types/usage';
import { TrendingUp, Activity, AlertCircle, DollarSign, Zap, Target } from 'lucide-react';

interface UsageStatsProps {
  stats: UsageStatsType | null;
  isLoading: boolean;
  error: string | null;
}

export function UsageStats({ stats, isLoading, error }: UsageStatsProps) {
  if (isLoading) {
    return (
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(250px, 1fr))',
          gap: '1rem',
          marginBottom: '2rem',
        }}
      >
        {[...Array(6)].map((_, i) => (
          <div
            key={i}
            style={{
              background: '#f8f9fa',
              borderRadius: '8px',
              padding: '1.5rem',
              border: '1px solid #e9ecef',
              textAlign: 'center',
            }}
          >
            <div
              style={{
                width: '24px',
                height: '24px',
                borderRadius: '50%',
                background: '#e9ecef',
                margin: '0 auto 1rem',
              }}
            />
            <div
              style={{
                height: '1.5rem',
                background: '#e9ecef',
                borderRadius: '4px',
                marginBottom: '0.5rem',
              }}
            />
            <div
              style={{
                height: '1rem',
                background: '#e9ecef',
                borderRadius: '4px',
                width: '60%',
                margin: '0 auto',
              }}
            />
          </div>
        ))}
      </div>
    );
  }

  if (error) {
    return (
      <div
        style={{
          background: '#f8d7da',
          border: '1px solid #f5c6cb',
          borderRadius: '8px',
          padding: '1rem',
          marginBottom: '2rem',
          display: 'flex',
          alignItems: 'center',
          gap: '0.5rem',
        }}
      >
        <AlertCircle size={20} style={{ color: '#721c24' }} />
        <span style={{ color: '#721c24' }}>Failed to load usage statistics: {error}</span>
      </div>
    );
  }

  if (!stats) {
    return (
      <div
        style={{
          textAlign: 'center',
          padding: '2rem',
          color: '#6c757d',
          background: '#f8f9fa',
          borderRadius: '8px',
          marginBottom: '2rem',
        }}
      >
        <Activity size={48} style={{ margin: '0 auto 1rem', opacity: 0.5 }} />
        <p>No usage data available for the selected period.</p>
      </div>
    );
  }

  const formatCurrency = (cost: number | string | null) => {
    if (cost === null || cost === undefined) return '$0.00';
    const costValue = typeof cost === 'string' ? parseFloat(cost) : cost;
    if (isNaN(costValue)) return '$0.00';
    return `$${costValue.toFixed(2)}`;
  };

  const formatPercentage = (rate: number) => {
    return `${(rate * 100).toFixed(1)}%`;
  };

  const statCards = [
    {
      icon: <Activity size={24} style={{ color: '#4f46e5' }} />,
      label: 'Total Requests',
      value: (stats.total_requests ?? 0).toLocaleString(),
      color: '#4f46e5',
      background: '#eef2ff',
    },
    {
      icon: <Target size={24} style={{ color: '#059669' }} />,
      label: 'Success Rate',
      value: formatPercentage(stats.success_rate ?? 0),
      color: '#059669',
      background: '#ecfdf5',
      subtitle: `${(stats.successful_requests ?? Math.round((stats.total_requests ?? 0) * (stats.success_rate ?? 0))).toLocaleString()} successful`,
    },
    {
      icon: <AlertCircle size={24} style={{ color: '#dc2626' }} />,
      label: 'Failed Requests',
      value: (
        stats.failed_requests ??
        Math.round((stats.total_requests ?? 0) * (1 - (stats.success_rate ?? 0)))
      ).toLocaleString(),
      color: '#dc2626',
      background: '#fef2f2',
    },
    {
      icon: <Zap size={24} style={{ color: '#ea580c' }} />,
      label: 'Total Tokens',
      value: (stats.total_tokens ?? 0).toLocaleString(),
      color: '#ea580c',
      background: '#fff7ed',
      subtitle: `↑ ${(stats.total_input_tokens ?? 0).toLocaleString()} ↓ ${(stats.total_output_tokens ?? 0).toLocaleString()}${
        (stats.total_cache_read_tokens ?? 0) > 0 || (stats.total_cache_write_tokens ?? 0) > 0
          ? ` • 📖 ${(stats.total_cache_read_tokens ?? 0).toLocaleString()} ✏️ ${(stats.total_cache_write_tokens ?? 0).toLocaleString()}`
          : ''
      }`,
    },
    {
      icon: <DollarSign size={24} style={{ color: '#16a34a' }} />,
      label: 'Total Cost',
      value: formatCurrency(stats.total_cost),
      color: '#16a34a',
      background: '#f0fdf4',
    },
    {
      icon: <TrendingUp size={24} style={{ color: '#7c3aed' }} />,
      label: 'Unique Models',
      value: (stats.unique_models ?? 0).toString(),
      color: '#7c3aed',
      background: '#faf5ff',
    },
  ];

  return (
    <div>
      {/* Date Range Info */}
      <div
        style={{
          background: '#f8f9fa',
          border: '1px solid #e9ecef',
          borderRadius: '8px',
          padding: '0.75rem 1rem',
          marginBottom: '1.5rem',
          fontSize: '0.875rem',
          color: '#6c757d',
          textAlign: 'center',
        }}
      >
        Usage statistics from {new Date(stats.start_date).toLocaleDateString()} to{' '}
        {new Date(stats.end_date).toLocaleDateString()} (times in UTC)
      </div>

      {/* Stats Grid */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))',
          gap: '1rem',
          marginBottom: '2rem',
        }}
      >
        {statCards.map((card, index) => (
          <div
            key={index}
            style={{
              background: 'white',
              borderRadius: '12px',
              padding: '1.5rem',
              border: `2px solid ${card.color}20`,
              boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1)',
              transition: 'transform 0.2s ease, box-shadow 0.2s ease',
            }}
            onMouseEnter={(e) => {
              e.currentTarget.style.transform = 'translateY(-2px)';
              e.currentTarget.style.boxShadow = '0 8px 25px -5px rgba(0, 0, 0, 0.1)';
            }}
            onMouseLeave={(e) => {
              e.currentTarget.style.transform = 'translateY(0)';
              e.currentTarget.style.boxShadow = '0 4px 6px -1px rgba(0, 0, 0, 0.1)';
            }}
          >
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                marginBottom: '1rem',
              }}
            >
              <div
                style={{
                  background: card.background,
                  borderRadius: '8px',
                  padding: '0.75rem',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                }}
              >
                {card.icon}
              </div>
            </div>

            <div
              style={{
                fontSize: '2rem',
                fontWeight: 'bold',
                color: card.color,
                marginBottom: '0.25rem',
                lineHeight: 1,
              }}
            >
              {card.value}
            </div>

            <div
              style={{
                fontSize: '0.875rem',
                color: '#6c757d',
                fontWeight: 500,
                marginBottom: card.subtitle ? '0.25rem' : 0,
              }}
            >
              {card.label}
            </div>

            {card.subtitle && (
              <div
                style={{
                  fontSize: '0.75rem',
                  color: '#9ca3af',
                }}
              >
                {card.subtitle}
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
