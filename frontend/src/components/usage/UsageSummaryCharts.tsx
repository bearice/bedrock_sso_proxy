import React, { useState, useMemo, useEffect } from 'react';
import { DollarSign, Zap, Activity, X, TrendingUp } from 'lucide-react';
import type { components } from '../../generated/api';

type UsageSummary = components['schemas']['UsageSummary'];

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
  timeSeriesData: Array<{
    date: string;
    value: number;
    modelBreakdown: Array<{ model_id: string; value: number }>;
    _mergeInfo?: {
      mergeFactor: number;
      startDate: string;
      endDate: string;
      periodType: string;
    };
  }>;
  modelBreakdown: ModelBreakdown[];
  primaryColor: string;
  backgroundColor: string;
  lastDayValue: number;
  lastWeekValue: number;
  unit: string;
}

export function UsageSummaryCharts({ summaries, isLoading, error }: UsageSummaryChartsProps) {
  const [popupChart, setPopupChart] = useState<string | null>(null);
  const [hoveredBar, setHoveredBar] = useState<{
    chartTitle: string;
    barIndex: number;
    x: number;
    y: number;
  } | null>(null);

  // Reset hover state when summaries change
  useEffect(() => {
    setHoveredBar(null);
  }, [summaries]);

  // Generate consistent color for model
  const getModelColor = (modelId: string, index: number = 0) => {
    const hash = modelId.split('').reduce((acc, char) => acc + char.charCodeAt(0), 0);
    return `hsl(${(hash * 137.508 + index * 30) % 360}, 70%, 50%)`;
  };

  // Calculate model breakdown from summaries (simple client-side aggregation)
  const modelBreakdown = useMemo(() => {
    const breakdown: Record<string, ModelBreakdown> = {};

    summaries.forEach((summary) => {
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
    Object.values(breakdown).forEach((model) => {
      model.avg_cost = model.total_requests > 0 ? model.total_cost / model.total_requests : 0;
    });

    return breakdown;
  }, [summaries]);

  // Generate time series data from summaries with intelligent time slot merging
  const timeSeriesData = useMemo(() => {
    if (summaries.length === 0) return {};

    // First, collect all data points by period type
    interface PeriodData {
      spend: number;
      tokens: number;
      requests: number;
      spendByModel: Record<string, number>;
      tokensByModel: Record<string, number>;
      requestsByModel: Record<string, number>;
      _mergeInfo?: {
        mergeFactor: number;
        startDate: string;
        endDate: string;
        periodType: string;
      };
    }

    const rawPeriodData: Record<string, PeriodData> = {};

    summaries.forEach((summary) => {
      let dateKey: string;
      const periodStart = new Date(summary.period_start);

      switch (summary.period_type) {
        case 'hourly':
          dateKey = periodStart.toISOString().substring(0, 13) + ':00:00.000Z';
          break;
        case 'weekly':
          dateKey = summary.period_start;
          break;
        case 'monthly':
          dateKey = new Date(periodStart.getFullYear(), periodStart.getMonth(), 1).toISOString();
          break;
        default:
        case 'daily':
          dateKey = periodStart.toISOString().split('T')[0] + 'T00:00:00.000Z';
          break;
      }

      const cost = parseFloat(summary.estimated_cost || '0');
      const modelId = summary.model_id;

      if (!rawPeriodData[dateKey]) {
        rawPeriodData[dateKey] = {
          spend: 0,
          tokens: 0,
          requests: 0,
          spendByModel: {},
          tokensByModel: {},
          requestsByModel: {},
        };
      }

      rawPeriodData[dateKey].spend += cost;
      rawPeriodData[dateKey].tokens += summary.total_tokens;
      rawPeriodData[dateKey].requests += summary.total_requests;
      rawPeriodData[dateKey].spendByModel[modelId] =
        (rawPeriodData[dateKey].spendByModel[modelId] || 0) + cost;
      rawPeriodData[dateKey].tokensByModel[modelId] =
        (rawPeriodData[dateKey].tokensByModel[modelId] || 0) + summary.total_tokens;
      rawPeriodData[dateKey].requestsByModel[modelId] =
        (rawPeriodData[dateKey].requestsByModel[modelId] || 0) + summary.total_requests;
    });

    // Determine period type and generate complete time range with empty slots
    const periodType = summaries[0]?.period_type || 'daily';
    const sortedDates = Object.keys(rawPeriodData).sort();

    if (sortedDates.length === 0) return {};

    const startDate = new Date(sortedDates[0]);
    const endDate = new Date(sortedDates[sortedDates.length - 1]);

    // Generate complete time series with empty slots
    const completeTimeSeriesData: typeof rawPeriodData = {};

    if (periodType === 'hourly') {
      // For hourly data, fill all hours between start and end
      const currentHour = new Date(startDate);
      while (currentHour <= endDate) {
        const hourKey = currentHour.toISOString().substring(0, 13) + ':00:00.000Z';
        completeTimeSeriesData[hourKey] = rawPeriodData[hourKey] || {
          spend: 0,
          tokens: 0,
          requests: 0,
          spendByModel: {},
          tokensByModel: {},
          requestsByModel: {},
        };
        currentHour.setUTCHours(currentHour.getUTCHours() + 1);
      }
    } else if (periodType === 'daily') {
      // For daily data, fill all days between start and end
      const currentDay = new Date(startDate);
      while (currentDay <= endDate) {
        const dayKey = currentDay.toISOString().split('T')[0] + 'T00:00:00.000Z';
        completeTimeSeriesData[dayKey] = rawPeriodData[dayKey] || {
          spend: 0,
          tokens: 0,
          requests: 0,
          spendByModel: {},
          tokensByModel: {},
          requestsByModel: {},
        };
        currentDay.setUTCDate(currentDay.getUTCDate() + 1);
      }
    } else {
      // For weekly/monthly, use raw data as-is
      Object.assign(completeTimeSeriesData, rawPeriodData);
    }

    // Now apply intelligent merging if we have too many data points
    const sortedCompleteEntries = Object.entries(completeTimeSeriesData).sort(([a], [b]) =>
      a.localeCompare(b)
    );
    const maxBars = 15;

    if (sortedCompleteEntries.length <= maxBars) {
      // No merging needed
      return completeTimeSeriesData;
    }

    // Calculate merge factor (how many time slots to combine into one bar)
    const mergeFactor = Math.ceil(sortedCompleteEntries.length / maxBars);
    const mergedData: Record<string, PeriodData> = {};

    for (let i = 0; i < sortedCompleteEntries.length; i += mergeFactor) {
      const chunk = sortedCompleteEntries.slice(i, i + mergeFactor);
      const firstDate = chunk[0][0];
      const lastDate = chunk[chunk.length - 1][0];

      // Create merged key representing the time range
      const mergedKey = firstDate; // Use first date as the key

      mergedData[mergedKey] = {
        spend: 0,
        tokens: 0,
        requests: 0,
        spendByModel: {},
        tokensByModel: {},
        requestsByModel: {},
      };

      // Merge all data in this chunk
      chunk.forEach(([, data]) => {
        mergedData[mergedKey].spend += data.spend;
        mergedData[mergedKey].tokens += data.tokens;
        mergedData[mergedKey].requests += data.requests;

        Object.entries(data.spendByModel).forEach(([model, spend]) => {
          mergedData[mergedKey].spendByModel[model] =
            (mergedData[mergedKey].spendByModel[model] || 0) + spend;
        });

        Object.entries(data.tokensByModel).forEach(([model, tokens]) => {
          mergedData[mergedKey].tokensByModel[model] =
            (mergedData[mergedKey].tokensByModel[model] || 0) + tokens;
        });

        Object.entries(data.requestsByModel).forEach(([model, requests]) => {
          mergedData[mergedKey].requestsByModel[model] =
            (mergedData[mergedKey].requestsByModel[model] || 0) + requests;
        });
      });

      // Store metadata about the merge for tooltip display
      mergedData[mergedKey]._mergeInfo = {
        mergeFactor,
        startDate: firstDate,
        endDate: lastDate,
        periodType,
      };
    }

    return mergedData;
  }, [summaries]);

  // Convert to sorted array - no need for additional optimization since we handle it above
  const sortedTimeSeriesEntries = useMemo(() => {
    const entries = Object.entries(timeSeriesData)
      .map(([date, data]) => ({ date, ...data }))
      .sort((a, b) => new Date(a.date).getTime() - new Date(b.date).getTime());

    return entries;
  }, [timeSeriesData]);

  // Calculate last day and last week values
  const getLastPeriodValues = (type: 'spend' | 'tokens' | 'requests') => {
    const now = new Date();
    const yesterday = new Date(now);
    yesterday.setDate(yesterday.getDate() - 1);

    const yesterdayKey = yesterday.toISOString().split('T')[0] + 'T00:00:00.000Z';
    const lastDayValue = timeSeriesData[yesterdayKey]?.[type] || 0;

    let lastWeekValue = 0;
    for (let i = 0; i < 7; i++) {
      const date = new Date(now);
      date.setDate(date.getDate() - i);
      const dateKey = date.toISOString().split('T')[0] + 'T00:00:00.000Z';
      lastWeekValue += timeSeriesData[dateKey]?.[type] || 0;
    }

    return { lastDayValue, lastWeekValue };
  };

  const spendPeriods = getLastPeriodValues('spend');
  const tokenPeriods = getLastPeriodValues('tokens');
  const requestPeriods = getLastPeriodValues('requests');

  // Calculate totals for all charts
  const totals = useMemo(() => {
    const totalSpend = Object.values(modelBreakdown).reduce(
      (sum, model) => sum + model.total_cost,
      0
    );
    const totalTokens = Object.values(modelBreakdown).reduce(
      (sum, model) => sum + model.total_tokens,
      0
    );
    const totalRequests = Object.values(modelBreakdown).reduce(
      (sum, model) => sum + model.total_requests,
      0
    );

    return { totalSpend, totalTokens, totalRequests };
  }, [modelBreakdown]);

  const charts: ChartData[] = [
    {
      title: 'Spend',
      icon: <DollarSign size={24} />,
      timeSeriesData: sortedTimeSeriesEntries.map((entry) => ({
        date: entry.date,
        value: entry.spend,
        modelBreakdown: Object.entries(entry.spendByModel).map(([model_id, value]) => ({
          model_id,
          value,
        })),
        _mergeInfo: entry._mergeInfo,
      })),
      modelBreakdown: Object.values(modelBreakdown).sort((a, b) => b.total_cost - a.total_cost),
      primaryColor: '#ff6b47',
      backgroundColor: '#fff5f5',
      lastDayValue: spendPeriods.lastDayValue,
      lastWeekValue: spendPeriods.lastWeekValue,
      unit: '$',
    },
    {
      title: 'Tokens',
      icon: <Zap size={24} />,
      timeSeriesData: sortedTimeSeriesEntries.map((entry) => ({
        date: entry.date,
        value: entry.tokens,
        modelBreakdown: Object.entries(entry.tokensByModel).map(([model_id, value]) => ({
          model_id,
          value,
        })),
        _mergeInfo: entry._mergeInfo,
      })),
      modelBreakdown: Object.values(modelBreakdown).sort((a, b) => b.total_tokens - a.total_tokens),
      primaryColor: '#3b82f6',
      backgroundColor: '#eff6ff',
      lastDayValue: tokenPeriods.lastDayValue,
      lastWeekValue: tokenPeriods.lastWeekValue,
      unit: 'token',
    },
    {
      title: 'Requests',
      icon: <Activity size={24} />,
      timeSeriesData: sortedTimeSeriesEntries.map((entry) => ({
        date: entry.date,
        value: entry.requests,
        modelBreakdown: Object.entries(entry.requestsByModel).map(([model_id, value]) => ({
          model_id,
          value,
        })),
        _mergeInfo: entry._mergeInfo,
      })),
      modelBreakdown: Object.values(modelBreakdown).sort(
        (a, b) => b.total_requests - a.total_requests
      ),
      primaryColor: '#10b981',
      backgroundColor: '#ecfdf5',
      lastDayValue: requestPeriods.lastDayValue,
      lastWeekValue: requestPeriods.lastWeekValue,
      unit: 'req',
    },
  ];

  const handleChartClick = (chartTitle: string) => {
    setPopupChart(chartTitle);
  };

  if (isLoading) {
    return (
      <div style={{ display: 'flex', gap: '1rem', marginBottom: '2rem' }}>
        {[1, 2, 3].map((i) => (
          <div
            key={i}
            style={{
              flex: 1,
              background: '#f8f9fa',
              borderRadius: '12px',
              padding: '1.5rem',
              border: '1px solid #e9ecef',
              height: '300px',
            }}
          >
            <div
              style={{
                width: '100%',
                height: '20px',
                background: '#e9ecef',
                borderRadius: '4px',
                marginBottom: '1rem',
              }}
            />
            <div
              style={{
                width: '100%',
                height: '200px',
                background: '#e9ecef',
                borderRadius: '4px',
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
          textAlign: 'center',
          color: '#721c24',
        }}
      >
        Error loading usage data: {error}
      </div>
    );
  }

  // Show message when no data is available
  if (!isLoading && summaries.length === 0) {
    return (
      <div
        style={{
          background: '#fff',
          border: '1px solid #e9ecef',
          borderRadius: '12px',
          padding: '2rem',
          marginBottom: '2rem',
          textAlign: 'center',
          color: '#6c757d',
        }}
      >
        <div style={{ marginBottom: '1rem', fontSize: '1.125rem', fontWeight: '500' }}>
          No usage data found
        </div>
        <div style={{ fontSize: '0.875rem' }}>
          Try adjusting your date range or filters to find data, or check back after making some API
          requests.
        </div>
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
              transition: 'transform 0.2s ease, box-shadow 0.2s ease',
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
            <div
              style={{
                padding: '1.5rem 1.5rem 0',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
                <h3
                  style={{
                    margin: 0,
                    display: 'flex',
                    alignItems: 'center',
                    gap: '0.5rem',
                    fontSize: '1.1rem',
                  }}
                >
                  {chart.icon}
                  {chart.title}
                </h3>
                <div
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: '0.25rem',
                    color: chart.primaryColor,
                    fontWeight: 'bold',
                    fontSize: '1.2rem',
                  }}
                >
                  <span style={{ fontSize: '0.9rem', color: '#6c757d' }}>Total:</span>
                  {chart.title === 'Spend' && '$'}
                  {chart.title === 'Spend' && totals.totalSpend.toFixed(2)}
                  {chart.title === 'Tokens' && totals.totalTokens.toLocaleString()}
                  {chart.title === 'Requests' && totals.totalRequests.toLocaleString()}
                </div>
              </div>
            </div>

            {/* Simple Chart Area */}
            <div style={{ padding: '1rem 1.5rem' }}>
              <div
                style={{
                  height: '120px',
                  background: chart.backgroundColor,
                  borderRadius: '8px',
                  position: 'relative',
                  overflow: 'hidden',
                  marginBottom: '1rem',
                }}
              >
                {/* Stacked bar chart visualization */}
                <div
                  style={{
                    position: 'absolute',
                    bottom: 0,
                    left: 0,
                    right: 0,
                    display: 'flex',
                    alignItems: 'end',
                    height: '100%',
                    padding: '8px',
                  }}
                >
                  {(() => {
                    // Show all available data since we already optimized it
                    const dataToShow = chart.timeSeriesData;

                    // Calculate max value from the data we're actually showing
                    const maxValue = Math.max(...dataToShow.map((p) => p.value));

                    // Handle empty data gracefully
                    if (dataToShow.length === 0) {
                      return (
                        <div
                          style={{
                            display: 'flex',
                            alignItems: 'center',
                            justifyContent: 'center',
                            height: '100%',
                            color: '#6c757d',
                            fontSize: '0.875rem',
                          }}
                        >
                          No data available
                        </div>
                      );
                    }

                    return dataToShow.map((point, index) => {
                      const totalHeight = maxValue > 0 ? (point.value / maxValue) * 100 : 0;

                      // Sort model breakdown by value (largest first for better visual stacking)
                      const sortedModels = point.modelBreakdown.sort((a, b) => b.value - a.value);

                      return (
                        <div
                          key={`${point.date}-${index}`}
                          style={{
                            flex: 1,
                            height: `${Math.max(totalHeight, point.value > 0 ? 2 : 1)}%`, // Ensure empty bars are visible
                            marginRight: index < dataToShow.length - 1 ? '2px' : 0,
                            borderRadius: '2px 2px 0 0',
                            minHeight: '2px', // Always show some height for empty bars
                            display: 'flex',
                            flexDirection: 'column',
                            justifyContent: 'end',
                            cursor: 'pointer',
                            position: 'relative',
                            border: point.value === 0 ? '1px solid #e5e7eb' : 'none', // Show border for empty bars
                            backgroundColor: point.value === 0 ? '#f9fafb' : 'transparent', // Light background for empty bars
                          }}
                          onMouseEnter={(e) => {
                            const rect = e.currentTarget.getBoundingClientRect();
                            setHoveredBar({
                              chartTitle: chart.title,
                              barIndex: index,
                              x: rect.left + rect.width / 2,
                              y: rect.top,
                            });
                          }}
                          onMouseLeave={() => setHoveredBar(null)}
                        >
                          {sortedModels.map((model, modelIndex) => {
                            const modelHeight =
                              point.value > 0 ? (model.value / point.value) * 100 : 0;
                            return (
                              <div
                                key={model.model_id}
                                style={{
                                  height: `${modelHeight}%`,
                                  background: getModelColor(model.model_id, modelIndex),
                                  borderRadius: modelIndex === 0 ? '2px 2px 0 0' : '0',
                                  minHeight: model.value > 0 ? '1px' : 0,
                                  transition: 'all 0.2s ease',
                                }}
                                onMouseEnter={(e) => {
                                  e.currentTarget.style.opacity = '0.8';
                                }}
                                onMouseLeave={(e) => {
                                  e.currentTarget.style.opacity = '1';
                                }}
                              />
                            );
                          })}
                        </div>
                      );
                    });
                  })()}
                </div>
              </div>

              {/* Summary Stats */}
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <div>
                  <div style={{ fontSize: '0.875rem', color: '#6c757d' }}>Last day</div>
                  <div style={{ fontWeight: 'bold', color: chart.primaryColor }}>
                    {chart.title === 'Spend' ? chart.unit : ''}
                    {chart.title === 'Tokens'
                      ? chart.lastDayValue.toLocaleString()
                      : chart.lastDayValue.toFixed(chart.title === 'Spend' ? 2 : 0)}
                  </div>
                </div>
                <div>
                  <div style={{ fontSize: '0.875rem', color: '#6c757d' }}>Last week</div>
                  <div style={{ fontWeight: 'bold', color: chart.primaryColor }}>
                    {chart.title === 'Spend' ? chart.unit : ''}
                    {chart.title === 'Tokens'
                      ? chart.lastWeekValue.toLocaleString()
                      : chart.lastWeekValue.toFixed(chart.title === 'Spend' ? 2 : 0)}
                  </div>
                </div>
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* Popup Modal */}
      {popupChart && (
        <div
          style={{
            position: 'fixed',
            top: 0,
            left: 0,
            right: 0,
            bottom: 0,
            backgroundColor: 'rgba(0, 0, 0, 0.5)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            zIndex: 1000,
            padding: '2rem',
          }}
          onClick={() => setPopupChart(null)}
        >
          <div
            style={{
              background: 'white',
              borderRadius: '12px',
              padding: '2rem',
              boxShadow: '0 8px 32px rgba(0,0,0,0.3)',
              maxWidth: '800px',
              width: '100%',
              maxHeight: '80vh',
              overflow: 'auto',
            }}
            onClick={(e) => e.stopPropagation()}
          >
            {/* Header */}
            <div
              style={{
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                marginBottom: '1.5rem',
                borderBottom: '1px solid #e9ecef',
                paddingBottom: '1rem',
              }}
            >
              <div>
                <h4
                  style={{
                    margin: '0 0 0.5rem 0',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '0.5rem',
                    fontSize: '1.25rem',
                  }}
                >
                  <TrendingUp size={24} />
                  Model {popupChart} Breakdown
                </h4>
                <p style={{ margin: 0, color: '#6c757d', fontSize: '0.875rem' }}>
                  Detailed breakdown by model for the selected period
                </p>
              </div>
              <button
                onClick={() => setPopupChart(null)}
                style={{
                  background: 'none',
                  border: 'none',
                  cursor: 'pointer',
                  padding: '0.5rem',
                  borderRadius: '50%',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  color: '#6c757d',
                  transition: 'all 0.2s ease',
                }}
                onMouseEnter={(e) => {
                  e.currentTarget.style.backgroundColor = '#f8f9fa';
                  e.currentTarget.style.color = '#000';
                }}
                onMouseLeave={(e) => {
                  e.currentTarget.style.backgroundColor = 'transparent';
                  e.currentTarget.style.color = '#6c757d';
                }}
              >
                <X size={20} />
              </button>
            </div>

            <div style={{ overflowX: 'auto' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                <thead>
                  <tr style={{ borderBottom: '2px solid #e9ecef' }}>
                    <th style={{ textAlign: 'left', padding: '0.75rem', fontWeight: '600' }}>
                      Model
                    </th>
                    {popupChart === 'Spend' && (
                      <>
                        <th style={{ textAlign: 'right', padding: '0.75rem', fontWeight: '600' }}>
                          Min ($)
                        </th>
                        <th style={{ textAlign: 'right', padding: '0.75rem', fontWeight: '600' }}>
                          Max ($)
                        </th>
                      </>
                    )}
                    {(popupChart === 'Spend' || popupChart === 'Tokens') && (
                      <th style={{ textAlign: 'right', padding: '0.75rem', fontWeight: '600' }}>
                        {popupChart === 'Spend'
                          ? 'Avg per Request ($)'
                          : 'Avg per Request (tokens)'}
                      </th>
                    )}
                    <th style={{ textAlign: 'right', padding: '0.75rem', fontWeight: '600' }}>
                      {popupChart === 'Spend'
                        ? 'Total Cost ($)'
                        : popupChart === 'Tokens'
                          ? 'Total Tokens'
                          : 'Total Requests'}
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {charts
                    .find((c) => c.title === popupChart)
                    ?.modelBreakdown.map((model, index) => {
                      const getValue = (type: 'min' | 'max' | 'avg' | 'sum') => {
                        switch (popupChart) {
                          case 'Spend': {
                            switch (type) {
                              case 'min':
                                return model.min_cost;
                              case 'max':
                                return model.max_cost;
                              case 'avg':
                                return model.avg_cost;
                              case 'sum':
                                return model.total_cost;
                            }
                            break;
                          }
                          case 'Tokens': {
                            const avgTokens = model.total_tokens / model.total_requests;
                            switch (type) {
                              case 'min':
                                return null; // Not available in summary data
                              case 'max':
                                return null; // Not available in summary data
                              case 'avg':
                                return avgTokens;
                              case 'sum':
                                return model.total_tokens;
                            }
                            break;
                          }
                          case 'Requests': {
                            switch (type) {
                              case 'min':
                                return null; // Not available in summary data
                              case 'max':
                                return null; // Not available in summary data
                              case 'avg':
                                return null; // Not meaningful for aggregated data
                              case 'sum':
                                return model.total_requests;
                            }
                            break;
                          }
                        }
                        return 0;
                      };

                      const formatValue = (value: number | null) => {
                        if (value === null) {
                          return '-';
                        }
                        if (popupChart === 'Spend') {
                          return value.toFixed(4);
                        } else if (popupChart === 'Tokens') {
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
                            backgroundColor: index % 2 === 0 ? '#fafbfc' : 'white',
                          }}
                        >
                          <td style={{ padding: '0.75rem' }}>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                              <div
                                style={{
                                  width: '12px',
                                  height: '12px',
                                  borderRadius: '50%',
                                  backgroundColor: getModelColor(model.model_id, index),
                                }}
                              />
                              <span style={{ fontFamily: 'monospace', fontSize: '0.875rem' }}>
                                {model.model_id}
                              </span>
                            </div>
                          </td>
                          {popupChart === 'Spend' && (
                            <>
                              <td style={{ textAlign: 'right', padding: '0.75rem' }}>
                                {formatValue(getValue('min'))}
                              </td>
                              <td style={{ textAlign: 'right', padding: '0.75rem' }}>
                                {formatValue(getValue('max'))}
                              </td>
                            </>
                          )}
                          {(popupChart === 'Spend' || popupChart === 'Tokens') && (
                            <td style={{ textAlign: 'right', padding: '0.75rem' }}>
                              {formatValue(getValue('avg'))}
                            </td>
                          )}
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
        </div>
      )}

      {/* Hover Tooltip */}
      {hoveredBar && (
        <div
          style={{
            position: 'fixed',
            left: `${hoveredBar.x}px`,
            top: `${hoveredBar.y - 10}px`,
            transform: 'translate(-50%, -100%)',
            background: 'rgba(0, 0, 0, 0.9)',
            color: 'white',
            padding: '0.75rem',
            borderRadius: '8px',
            fontSize: '0.875rem',
            boxShadow: '0 4px 12px rgba(0,0,0,0.3)',
            zIndex: 1001,
            pointerEvents: 'none',
            maxWidth: '280px',
            minWidth: '200px',
          }}
        >
          {(() => {
            const chart = charts.find((c) => c.title === hoveredBar.chartTitle);
            if (!chart) return null;

            // Use the chart's time series data directly
            const point = chart.timeSeriesData[hoveredBar.barIndex];

            if (!point) return null;

            const sortedModels = point.modelBreakdown.sort((a, b) => b.value - a.value);

            // Smart date formatting based on the period type inferred from summaries and merge info
            const formatDateForDisplay = (
              dateString: string,
              mergeInfo?: {
                mergeFactor: number;
                startDate: string;
                endDate: string;
                periodType: string;
              }
            ) => {
              const date = new Date(dateString);

              if (mergeInfo) {
                // Handle merged time ranges
                const startDate = new Date(mergeInfo.startDate);
                const endDate = new Date(mergeInfo.endDate);
                const { mergeFactor, periodType } = mergeInfo;

                if (periodType === 'hourly') {
                  const startHour = startDate.getUTCHours();
                  const endHour = new Date(endDate).getUTCHours();
                  const dayStr = startDate.toLocaleDateString('en-US', {
                    month: 'short',
                    day: 'numeric',
                  });

                  if (startDate.toDateString() === endDate.toDateString()) {
                    // Same day
                    return `${dayStr}, ${startHour}:00-${endHour + 1}:00 (${mergeFactor}h)`;
                  } else {
                    // Cross-day
                    const startStr = startDate.toLocaleDateString('en-US', {
                      month: 'short',
                      day: 'numeric',
                    });
                    const endStr = endDate.toLocaleDateString('en-US', {
                      month: 'short',
                      day: 'numeric',
                    });
                    return `${startStr} ${startHour}:00 - ${endStr} ${endHour + 1}:00`;
                  }
                } else if (periodType === 'daily') {
                  if (mergeFactor === 1) {
                    return date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
                  } else {
                    const startStr = startDate.toLocaleDateString('en-US', {
                      month: 'short',
                      day: 'numeric',
                    });
                    const endStr = endDate.toLocaleDateString('en-US', {
                      month: 'short',
                      day: 'numeric',
                    });
                    return `${startStr} - ${endStr} (${mergeFactor} days)`;
                  }
                }
              }

              // Regular formatting for non-merged data
              const hasHourlyData = summaries.some((s) => s.period_type === 'hourly');
              const hasWeeklyData = summaries.some((s) => s.period_type === 'weekly');
              const hasMonthlyData = summaries.some((s) => s.period_type === 'monthly');

              if (hasHourlyData) {
                return date.toLocaleDateString('en-US', {
                  month: 'short',
                  day: 'numeric',
                  hour: 'numeric',
                  hour12: true,
                });
              } else if (hasWeeklyData) {
                const endOfWeek = new Date(date);
                endOfWeek.setDate(endOfWeek.getDate() + 6);
                return `${date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' })} - ${endOfWeek.toLocaleDateString('en-US', { month: 'short', day: 'numeric' })}`;
              } else if (hasMonthlyData) {
                return date.toLocaleDateString('en-US', { month: 'long', year: 'numeric' });
              } else {
                return date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
              }
            };

            const displayDate = formatDateForDisplay(point.date, point._mergeInfo);

            return (
              <div>
                <div
                  style={{
                    fontWeight: 'bold',
                    marginBottom: '0.5rem',
                    borderBottom: '1px solid rgba(255,255,255,0.3)',
                    paddingBottom: '0.25rem',
                  }}
                >
                  {chart.title} - {displayDate}
                </div>
                <div style={{ marginBottom: '0.5rem' }}>
                  <strong>Total: </strong>
                  {chart.title === 'Spend' ? chart.unit : ''}
                  {chart.title === 'Tokens'
                    ? point.value.toLocaleString()
                    : point.value.toFixed(chart.title === 'Spend' ? 4 : 0)}
                </div>

                {sortedModels.length > 0 && (
                  <div>
                    <div style={{ fontSize: '0.8rem', marginBottom: '0.25rem', opacity: 0.8 }}>
                      Model Breakdown:
                    </div>
                    {sortedModels.slice(0, 5).map((model, index) => {
                      const percentage = point.value > 0 ? (model.value / point.value) * 100 : 0;
                      return (
                        <div
                          key={model.model_id}
                          style={{
                            display: 'flex',
                            alignItems: 'center',
                            justifyContent: 'space-between',
                            marginBottom: '0.25rem',
                            fontSize: '0.8rem',
                          }}
                        >
                          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                            <div
                              style={{
                                width: '8px',
                                height: '8px',
                                borderRadius: '50%',
                                backgroundColor: getModelColor(model.model_id, index),
                                flexShrink: 0,
                              }}
                            />
                            <span
                              style={{
                                fontFamily: 'monospace',
                                maxWidth: '120px',
                                overflow: 'hidden',
                                textOverflow: 'ellipsis',
                                whiteSpace: 'nowrap',
                              }}
                            >
                              {model.model_id}
                            </span>
                          </div>
                          <div style={{ textAlign: 'right', minWidth: '60px' }}>
                            <div>
                              {chart.title === 'Spend' ? chart.unit : ''}
                              {chart.title === 'Tokens'
                                ? model.value.toLocaleString()
                                : model.value.toFixed(chart.title === 'Spend' ? 4 : 0)}
                            </div>
                            <div style={{ opacity: 0.7, fontSize: '0.7rem' }}>
                              {percentage.toFixed(1)}%
                            </div>
                          </div>
                        </div>
                      );
                    })}
                    {sortedModels.length > 5 && (
                      <div style={{ fontSize: '0.7rem', opacity: 0.7, textAlign: 'center' }}>
                        +{sortedModels.length - 5} more models
                      </div>
                    )}
                  </div>
                )}
              </div>
            );
          })()}
        </div>
      )}
    </div>
  );
}
