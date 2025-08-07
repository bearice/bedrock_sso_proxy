import { useQuery } from '@tanstack/react-query';
import { apiClient, setAuthToken, ApiError } from '../../lib/api-client';
import type { components } from '../../generated/api';

// Type aliases for better readability
type UsageRecordsResponse = components['schemas']['UsageRecordsResponse'];
type UsageSummariesResponse = components['schemas']['UsageSummariesResponse'];
type UsageRecordsQuery = components['schemas']['UsageRecordsQuery'];
type UsageSummariesQuery = components['schemas']['UsageSummariesQuery'];

// Get user's usage records
export function useUserUsageRecords(token?: string, query?: Partial<UsageRecordsQuery>) {
  return useQuery({
    queryKey: ['usage', 'records', token, query],
    queryFn: async (): Promise<UsageRecordsResponse> => {
      if (!token) {
        throw new Error('No token provided');
      }

      setAuthToken(token);
      const { data, error } = await apiClient.GET('/api/usage/records', {
        params: {
          query: query || {},
        },
      });

      if (error) {
        throw new ApiError(500, error.error || 'Failed to fetch usage records');
      }
      return data as UsageRecordsResponse;
    },
    enabled: !!token,
  });
}

// Get user's usage summaries
export function useUserUsageSummaries(token?: string, query?: Partial<UsageSummariesQuery>) {
  return useQuery({
    queryKey: ['usage', 'summaries', token, query],
    queryFn: async (): Promise<UsageSummariesResponse> => {
      if (!token) {
        throw new Error('No token provided');
      }

      setAuthToken(token);
      const { data, error } = await apiClient.GET('/api/usage/summaries', {
        params: {
          query: query || {},
        },
      });

      if (error) {
        throw new ApiError(500, error.error || 'Failed to fetch usage summaries');
      }
      return data as UsageSummariesResponse;
    },
    enabled: !!token,
  });
}

// Admin endpoints for system-wide usage (future use)
export function useSystemUsageRecords(token?: string, query?: Partial<UsageRecordsQuery>) {
  return useQuery({
    queryKey: ['usage', 'admin', 'records', token, query],
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

export function useAdminUsageSummaries(token?: string, query?: Partial<UsageSummariesQuery>) {
  return useQuery({
    queryKey: ['usage', 'admin', 'summaries', token, query],
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

// Export usage data as CSV
export function useExportUsageData(
  token?: string,
  query?: {
    start_date?: string;
    end_date?: string;
    model?: string;
    success?: boolean;
    format: 'csv';
  }
) {
  return useQuery({
    queryKey: ['usage', 'export', token, query],
    queryFn: async (): Promise<Blob> => {
      if (!token) {
        throw new Error('No token provided');
      }

      setAuthToken(token);

      // Use fetch directly for blob response
      const params = new URLSearchParams();
      if (query?.start_date) params.append('start_date', query.start_date);
      if (query?.end_date) params.append('end_date', query.end_date);
      if (query?.model) params.append('model', query.model);
      if (query?.success !== undefined) params.append('success_only', query.success.toString());
      params.append('format', 'csv');

      const response = await fetch('/api/usage/records?' + params.toString(), {
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
