import React, { useState, useMemo } from 'react';
import { 
  DollarSign, 
  Zap, 
  Activity, 
  ChevronDown, 
  ChevronUp,
  TrendingUp
} from 'lucide-react';
import { UsageSummary } from '../../types/usage';

interface UsageSummaryChartsProps {
  summaries: UsageSummary[];
  isLoading: boolean;
  error: string | null;
}

interface ModelBreakdown {
  model_id: string;
  total_cost: number;
  total_tokens: number;
  total_requests: number;
  min_cost: number;
  max_cost: number;
  avg_cost: number;
}

interface ChartData {
  title: string;
  icon: React.ReactNode;
  timeSeriesData: Array<{ date: string; value: number; }>;
  modelBreakdown: ModelBreakdown[];
  primaryColor: string;
  backgroundColor: string;
  lastDayValue: number;
  lastWeekValue: number;
  unit: string;
}

export function UsageSummaryCharts({ summaries, isLoading, error }: UsageSummaryChartsProps) {
  const [expandedChart, setExpandedChart] = useState<string | null>(null);

  // Calculate model breakdown from summaries (simple client-side aggregation)
  const modelBreakdown = useMemo(() => {
    const breakdown: Record<string, ModelBreakdown> = {};
    
    summaries.forEach(summary => {
      const modelId = summary.model_id;
      const cost = parseFloat(summary.estimated_cost || '0');
      
      if (!breakdown[modelId]) {
        breakdown[modelId] = {
          model_id: modelId,
          total_cost: 0,
          total_tokens: 0,
          total_requests: 0,
          min_cost: cost,
          max_cost: cost,
          avg_cost: 0,
        };
      }
      
      breakdown[modelId].total_cost += cost;
      breakdown[modelId].total_tokens += summary.total_tokens;
      breakdown[modelId].total_requests += summary.total_requests;
      breakdown[modelId].min_cost = Math.min(breakdown[modelId].min_cost, cost);
      breakdown[modelId].max_cost = Math.max(breakdown[modelId].max_cost, cost);
    });

    // Calculate averages
    Object.values(breakdown).forEach(model => {
      model.avg_cost = model.total_requests > 0 ? model.total_cost / model.total_requests : 0;
    });

    return breakdown;
  }, [summaries]);

  // Generate time series data from summaries (already time-bucketed!)
  const timeSeriesData = useMemo(() => {
    const dailyData: Record<string, { spend: number; tokens: number; requests: number; }> = {};
    
    summaries.forEach(summary => {
      // summaries are already grouped by period, just use period_start
      const date = new Date(summary.period_start).toISOString().split('T')[0];
      const cost = parseFloat(summary.estimated_cost || '0');
      
      if (!dailyData[date]) {
        dailyData[date] = { spend: 0, tokens: 0, requests: 0 };
      }
      
      dailyData[date].spend += cost;
      dailyData[date].tokens += summary.total_tokens;
      dailyData[date].requests += summary.total_requests;
    });

    return dailyData;
  }, [summaries]);

  // Calculate last day and last week values
  const getLastPeriodValues = (type: 'spend' | 'tokens' | 'requests') => {
    const now = new Date();
    const yesterday = new Date(now);
    yesterday.setDate(yesterday.getDate() - 1);
    
    const yesterdayKey = yesterday.toISOString().split('T')[0];
    const lastDayValue = timeSeriesData[yesterdayKey]?.[type] || 0;

    let lastWeekValue = 0;
    for (let i = 0; i < 7; i++) {
      const date = new Date(now);
      date.setDate(date.getDate() - i);
      const dateKey = date.toISOString().split('T')[0];
      lastWeekValue += timeSeriesData[dateKey]?.[type] || 0;
    }

    return { lastDayValue, lastWeekValue };
  };

  const spendPeriods = getLastPeriodValues('spend');
  const tokenPeriods = getLastPeriodValues('tokens');
  const requestPeriods = getLastPeriodValues('requests');

  const charts: ChartData[] = [
    {
      title: 'Spend',
      icon: <DollarSign size={24} />,
      timeSeriesData: Object.entries(timeSeriesData).map(([date, data]) => ({
        date,
        value: data.spend
      })),
      modelBreakdown: Object.values(modelBreakdown).sort((a, b) => b.total_cost - a.total_cost),
      primaryColor: '#ff6b47',
      backgroundColor: '#fff5f5',
      lastDayValue: spendPeriods.lastDayValue,
      lastWeekValue: spendPeriods.lastWeekValue,
      unit: '$'
    },
    {
      title: 'Tokens',
      icon: <Zap size={24} />,
      timeSeriesData: Object.entries(timeSeriesData).map(([date, data]) => ({
        date,
        value: data.tokens
      })),
      modelBreakdown: Object.values(modelBreakdown).sort((a, b) => b.total_tokens - a.total_tokens),
      primaryColor: '#ff6b47',
      backgroundColor: '#fff5f5',
      lastDayValue: tokenPeriods.lastDayValue,
      lastWeekValue: tokenPeriods.lastWeekValue,
      unit: 'token'
    },
    {
      title: 'Requests',
      icon: <Activity size={24} />,
      timeSeriesData: Object.entries(timeSeriesData).map(([date, data]) => ({
        date,
        value: data.requests
      })),
      modelBreakdown: Object.values(modelBreakdown).sort((a, b) => b.total_requests - a.total_requests),
      primaryColor: '#ff6b47',
      backgroundColor: '#fff5f5',
      lastDayValue: requestPeriods.lastDayValue,
      lastWeekValue: requestPeriods.lastWeekValue,
      unit: 'req'
    }
  ];

  const handleChartClick = (chartTitle: string) => {
    setExpandedChart(expandedChart === chartTitle ? null : chartTitle);
  };

  if (isLoading) {
    return (
      <div style={{ display: 'flex', gap: '1rem', marginBottom: '2rem' }}>
        {[1, 2, 3].map(i => (
          <div
            key={i}
            style={{
              flex: 1,
              background: '#f8f9fa',
              borderRadius: '12px',
              padding: '1.5rem',
              border: '1px solid #e9ecef',
              height: '300px'
            }}
          >
            <div style={{ 
              width: '100%', 
              height: '20px', 
              background: '#e9ecef', 
              borderRadius: '4px',
              marginBottom: '1rem'
            }} />
            <div style={{ 
              width: '100%', 
              height: '200px', 
              background: '#e9ecef', 
              borderRadius: '4px'
            }} />
          </div>
        ))}
      </div>
    );
  }

  if (error) {
    return (
      <div style={{
        background: '#f8d7da',
        border: '1px solid #f5c6cb',
        borderRadius: '8px',
        padding: '1rem',
        marginBottom: '2rem',
        textAlign: 'center',
        color: '#721c24'
      }}>
        Error loading usage data: {error}
      </div>
    );
  }

  return (
    <div style={{ marginBottom: '2rem' }}>
      {/* Chart Cards */}
      <div style={{ display: 'flex', gap: '1rem', marginBottom: '1rem' }}>
        {charts.map((chart) => (
          <div
            key={chart.title}
            style={{
              flex: 1,
              background: 'white',
              borderRadius: '12px',
              border: '1px solid #e9ecef',
              overflow: 'hidden',
              boxShadow: '0 2px 4px rgba(0,0,0,0.1)',
              cursor: 'pointer',
              transition: 'transform 0.2s ease, box-shadow 0.2s ease'
            }}
            onClick={() => handleChartClick(chart.title)}
            onMouseEnter={(e) => {
              e.currentTarget.style.transform = 'translateY(-2px)';
              e.currentTarget.style.boxShadow = '0 4px 12px rgba(0,0,0,0.15)';
            }}
            onMouseLeave={(e) => {
              e.currentTarget.style.transform = 'translateY(0)';
              e.currentTarget.style.boxShadow = '0 2px 4px rgba(0,0,0,0.1)';
            }}
          >
            {/* Chart Header */}
            <div style={{ padding: '1.5rem 1.5rem 0', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
              <h3 style={{ margin: 0, display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '1.1rem' }}>
                {chart.icon}
                {chart.title}
              </h3>
              {expandedChart === chart.title ? <ChevronUp size={20} /> : <ChevronDown size={20} />}
            </div>

            {/* Simple Chart Area */}
            <div style={{ padding: '1rem 1.5rem' }}>
              <div style={{ 
                height: '120px', 
                background: chart.backgroundColor,
                borderRadius: '8px',
                position: 'relative',
                overflow: 'hidden',
                marginBottom: '1rem'
              }}>
                {/* Simple bar chart visualization */}
                <div style={{
                  position: 'absolute',
                  bottom: 0,
                  left: 0,
                  right: 0,
                  display: 'flex',
                  alignItems: 'end',
                  height: '100%',
                  padding: '8px'
                }}>
                  {chart.timeSeriesData.slice(-10).map((point, index) => {
                    const maxValue = Math.max(...chart.timeSeriesData.map(p => p.value));
                    const height = maxValue > 0 ? (point.value / maxValue) * 100 : 0;
                    return (
                      <div
                        key={index}
                        style={{
                          flex: 1,
                          background: chart.primaryColor,
                          height: `${height}%`,
                          marginRight: index < chart.timeSeriesData.slice(-10).length - 1 ? '2px' : 0,
                          borderRadius: '2px 2px 0 0',
                          minHeight: point.value > 0 ? '2px' : 0
                        }}
                      />
                    );
                  })}
                </div>
              </div>

              {/* Summary Stats */}
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <div>
                  <div style={{ fontSize: '0.875rem', color: '#6c757d' }}>Last day</div>
                  <div style={{ fontWeight: 'bold', color: chart.primaryColor }}>
                    {chart.unit}{chart.title === 'Tokens' ? chart.lastDayValue.toLocaleString() : chart.lastDayValue.toFixed(chart.title === 'Spend' ? 2 : 0)}
                  </div>
                </div>
                <div>
                  <div style={{ fontSize: '0.875rem', color: '#6c757d' }}>Last week</div>
                  <div style={{ fontWeight: 'bold', color: chart.primaryColor }}>
                    {chart.unit}{chart.title === 'Tokens' ? chart.lastWeekValue.toLocaleString() : chart.lastWeekValue.toFixed(chart.title === 'Spend' ? 2 : 0)}
                  </div>
                </div>
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* Expanded Chart Details */}
      {expandedChart && (
        <div style={{
          background: 'white',
          borderRadius: '12px',
          border: '1px solid #e9ecef',
          padding: '1.5rem',
          boxShadow: '0 4px 12px rgba(0,0,0,0.1)'
        }}>
          <div style={{ marginBottom: '1rem' }}>
            <h4 style={{ margin: '0 0 0.5rem 0', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <TrendingUp size={20} />
              Model {expandedChart}
            </h4>
            <p style={{ margin: 0, color: '#6c757d', fontSize: '0.875rem' }}>
              Breakdown by model for the selected period
            </p>
          </div>

          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse' }}>
              <thead>
                <tr style={{ borderBottom: '2px solid #e9ecef' }}>
                  <th style={{ textAlign: 'left', padding: '0.75rem', fontWeight: '600' }}>Model</th>
                  <th style={{ textAlign: 'right', padding: '0.75rem', fontWeight: '600' }}>
                    Min ({expandedChart === 'Spend' ? '$' : expandedChart === 'Tokens' ? '' : ''})
                  </th>
                  <th style={{ textAlign: 'right', padding: '0.75rem', fontWeight: '600' }}>
                    Max ({expandedChart === 'Spend' ? '$' : expandedChart === 'Tokens' ? '' : ''})
                  </th>
                  <th style={{ textAlign: 'right', padding: '0.75rem', fontWeight: '600' }}>
                    Avg ({expandedChart === 'Spend' ? '$' : expandedChart === 'Tokens' ? '' : ''})
                  </th>
                  <th style={{ textAlign: 'right', padding: '0.75rem', fontWeight: '600' }}>
                    Sum ({expandedChart === 'Spend' ? '$' : expandedChart === 'Tokens' ? '' : ''})
                  </th>
                </tr>
              </thead>
              <tbody>
                {charts.find(c => c.title === expandedChart)?.modelBreakdown.map((model, index) => {
                  const getValue = (type: 'min' | 'max' | 'avg' | 'sum') => {
                    switch (expandedChart) {
                      case 'Spend': {
                        switch (type) {
                          case 'min': return model.min_cost;
                          case 'max': return model.max_cost;
                          case 'avg': return model.avg_cost;
                          case 'sum': return model.total_cost;
                        }
                        break;
                      }
                      case 'Tokens': {
                        const avgTokens = model.total_tokens / model.total_requests;
                        switch (type) {
                          case 'min': return 0; // Min tokens per request not tracked in summaries
                          case 'max': return 0; // Max tokens per request not tracked in summaries
                          case 'avg': return avgTokens;
                          case 'sum': return model.total_tokens;
                        }
                        break;
                      }
                      case 'Requests': {
                        switch (type) {
                          case 'min': return 1; // Each summary period represents at least 1 request
                          case 'max': return model.total_requests; // Max in a single period
                          case 'avg': return model.total_requests; // Average per period would need more data
                          case 'sum': return model.total_requests;
                        }
                        break;
                      }
                    }
                    return 0;
                  };

                  const formatValue = (value: number) => {
                    if (expandedChart === 'Spend') {
                      return value.toFixed(4);
                    } else if (expandedChart === 'Tokens') {
                      return value.toLocaleString();
                    } else {
                      return value.toString();
                    }
                  };

                  return (
                    <tr
                      key={model.model_id}
                      style={{
                        borderBottom: '1px solid #f1f3f4',
                        backgroundColor: index % 2 === 0 ? '#fafbfc' : 'white'
                      }}
                    >
                      <td style={{ padding: '0.75rem' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                          <div
                            style={{
                              width: '12px',
                              height: '12px',
                              borderRadius: '50%',
                              backgroundColor: `hsl(${(index * 137.508) % 360}, 70%, 50%)`
                            }}
                          />
                          <span style={{ fontFamily: 'monospace', fontSize: '0.875rem' }}>
                            {model.model_id}
                          </span>
                        </div>
                      </td>
                      <td style={{ textAlign: 'right', padding: '0.75rem' }}>
                        {formatValue(getValue('min'))}
                      </td>
                      <td style={{ textAlign: 'right', padding: '0.75rem' }}>
                        {formatValue(getValue('max'))}
                      </td>
                      <td style={{ textAlign: 'right', padding: '0.75rem' }}>
                        {formatValue(getValue('avg'))}
                      </td>
                      <td style={{ textAlign: 'right', padding: '0.75rem', fontWeight: '600' }}>
                        {formatValue(getValue('sum'))}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}