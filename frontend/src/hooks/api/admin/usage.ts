import { useQuery } from '@tanstack/react-query';
import { apiClient, setAuthToken, ApiError } from '../../../lib/api-client';
import type { components } from '../../../generated/api';

// Type aliases for better readability
type UsageRecordsResponse = components['schemas']['UsageRecordsResponse'];
type UsageSummariesResponse = components['schemas']['UsageSummariesResponse'];
type UsageRecordsQuery = components['schemas']['UsageRecordsQuery'];
type UsageSummariesQuery = components['schemas']['UsageSummariesQuery'];

// ============================================================================
// SYSTEM-WIDE USAGE ANALYTICS HOOKS (ADMIN ONLY)
// ============================================================================

/**
 * Get system-wide usage records (admin only)
 */
export function useAdminUsageRecords(token?: string, query?: Partial<UsageRecordsQuery>) {
  return useQuery({
    queryKey: ['admin', 'usage', 'records', token, query],
    queryFn: async (): Promise<UsageRecordsResponse> => {
      if (!token) {
        throw new Error('No token provided');
      }

      setAuthToken(token);
      const { data, error } = await apiClient.GET('/api/admin/usage/records', {
        params: {
          query: query || {},
        },
      });

      if (error) {
        throw new ApiError(500, error.error || 'Failed to fetch system usage records');
      }
      return data as UsageRecordsResponse;
    },
    enabled: !!token,
  });
}

/**
 * Get system-wide usage summaries (admin only)
 */
export function useAdminUsageSummaries(token?: string, query?: Partial<UsageSummariesQuery>) {
  return useQuery({
    queryKey: ['admin', 'usage', 'summaries', token, query],
    queryFn: async (): Promise<UsageSummariesResponse> => {
      if (!token) {
        throw new Error('No token provided');
      }

      setAuthToken(token);
      const { data, error } = await apiClient.GET('/api/admin/usage/summaries', {
        params: {
          query: query || {},
        },
      });

      if (error) {
        throw new ApiError(500, error.error || 'Failed to fetch admin usage summaries');
      }
      return data as UsageSummariesResponse;
    },
    enabled: !!token,
  });
}

/**
 * Export system-wide usage data as CSV (admin only)
 */
export function useAdminExportUsageData(
  token?: string,
  query?: {
    start_date?: string;
    end_date?: string;
    model?: string;
    user_id?: number;
    success_only?: boolean;
    format: 'csv';
  }
) {
  return useQuery({
    queryKey: ['admin', 'usage', 'export', token, query],
    queryFn: async (): Promise<Blob> => {
      if (!token) {
        throw new Error('No token provided');
      }

      // Use fetch directly for blob response
      const params = new URLSearchParams();
      if (query?.start_date) params.append('start_date', query.start_date);
      if (query?.end_date) params.append('end_date', query.end_date);
      if (query?.model) params.append('model', query.model);
      if (query?.user_id) params.append('user_id', query.user_id.toString());
      if (query?.success_only !== undefined)
        params.append('success_only', query.success_only.toString());
      params.append('format', 'csv');

      const response = await fetch('/api/admin/usage/records?' + params.toString(), {
        headers: {
          Authorization: `Bearer ${token}`,
        },
      });

      if (!response.ok) {
        const errorText = await response.text();
        throw new ApiError(response.status, `Export failed: ${errorText}`);
      }

      return response.blob();
    },
    enabled: false, // Don't auto-fetch, only when manually triggered
  });
}

/**
 * Hook for getting usage statistics across time periods (admin only)
 */
export function useAdminUsageStats(
  token?: string,
  periods: ('hourly' | 'daily' | 'weekly' | 'monthly')[] = ['daily']
) {
  return useQuery({
    queryKey: ['admin', 'usage', 'stats', token, periods],
    queryFn: async () => {
      if (!token) {
        throw new Error('No token provided');
      }

      setAuthToken(token);

      // Fetch summaries for each period
      const results = await Promise.all(
        periods.map(async (period) => {
          const { data, error } = await apiClient.GET('/api/admin/usage/summaries', {
            params: {
              query: { period_type: period },
            },
          });

          if (error) {
            throw new ApiError(500, `Failed to fetch ${period} summaries`);
          }

          return { period, data };
        })
      );

      return results.reduce(
        (acc, { period, data }) => {
          acc[period] = data;
          return acc;
        },
        {} as Record<string, UsageSummariesResponse>
      );
    },
    enabled: !!token && periods.length > 0,
  });
}
