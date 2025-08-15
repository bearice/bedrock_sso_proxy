import { useQuery } from '@tanstack/react-query';
import { apiClient, ApiError } from '../../../lib/api-client';
import type { components } from '../../../generated/api';

// Type aliases for better readability
type AuditLogsResponse = components['schemas']['AuditLogsResponse'];
type AuditLogQueryParams = components['schemas']['AuditLogQueryParams'];

// ============================================================================
// AUDIT LOG HOOKS
// ============================================================================

/**
 * Get audit logs with filtering (admin only)
 */
export function useAdminAuditLogs(token?: string, query?: Partial<AuditLogQueryParams>) {
  return useQuery({
    queryKey: ['admin', 'audit-logs', token, query],
    queryFn: async (): Promise<AuditLogsResponse> => {
      if (!token) {
        throw new Error('No token provided');
      }

      const { data, error } = await apiClient.GET('/api/admin/audit-logs', {
        params: {
          query: query || {},
        },
        headers: {
          Authorization: `Bearer ${token}`,
        },
      });

      if (error) {
        throw new ApiError(500, error.error || 'Failed to fetch audit logs');
      }
      return data as AuditLogsResponse;
    },
    enabled: !!token,
  });
}
