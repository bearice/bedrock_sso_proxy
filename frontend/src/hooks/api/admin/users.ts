import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { apiClient, setAuthToken, ApiError } from '../../../lib/api-client';
import type { components } from '../../../generated/api';

// Type aliases for better readability
type UserResponse = components['schemas']['UserResponse'];
type UserListResponse = components['schemas']['UserListResponse'];
type UpdateUserStateRequest = components['schemas']['UpdateUserStateRequest'];

// ============================================================================
// USER MANAGEMENT HOOKS
// ============================================================================

/**
 * Get all users (admin only)
 */
export function useAdminUsers(token?: string, limit?: number, offset?: number) {
  return useQuery({
    queryKey: ['admin', 'users', token, limit, offset],
    queryFn: async (): Promise<UserListResponse> => {
      if (!token) {
        throw new Error('No token provided');
      }

      setAuthToken(token);
      const { data, error } = await apiClient.GET('/api/admin/users', {
        params: {
          query: {
            ...(limit !== undefined && { limit }),
            ...(offset !== undefined && { offset }),
          },
        },
      });

      if (error) {
        throw new ApiError(500, error.error || 'Failed to fetch users');
      }
      return data as UserListResponse;
    },
    enabled: !!token,
  });
}

/**
 * Search users by email (admin only)
 */
export function useAdminUserSearch(token?: string, q?: string) {
  return useQuery({
    queryKey: ['admin', 'users', 'search', token, q],
    queryFn: async (): Promise<UserListResponse> => {
      if (!token || !q) {
        throw new Error('No token or search query provided');
      }

      setAuthToken(token);
      const { data, error } = await apiClient.GET('/api/admin/users/search', {
        params: {
          query: { q },
        },
      });

      if (error) {
        throw new ApiError(500, error.error || 'Failed to search users');
      }
      return data as UserListResponse;
    },
    enabled: !!token && !!q,
  });
}

/**
 * Get specific user by ID (admin only)
 */
export function useAdminUser(token?: string, userId?: number) {
  return useQuery({
    queryKey: ['admin', 'users', userId, token],
    queryFn: async (): Promise<UserResponse> => {
      if (!token || !userId) {
        throw new Error('No token or user ID provided');
      }

      setAuthToken(token);
      const { data, error } = await apiClient.GET('/api/admin/users/{user_id}', {
        params: {
          path: { user_id: userId },
        },
      });

      if (error) {
        throw new ApiError(500, error.error || 'Failed to fetch user');
      }
      return data as UserResponse;
    },
    enabled: !!token && !!userId,
  });
}

/**
 * Update user state (enable/disable) - admin only
 */
export function useUpdateUserState(token?: string) {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: async ({
      userId,
      stateUpdate,
    }: {
      userId: number;
      stateUpdate: UpdateUserStateRequest;
    }) => {
      if (!token) {
        throw new Error('No token provided');
      }

      setAuthToken(token);
      const { data, error } = await apiClient.PUT('/api/admin/users/{user_id}/state', {
        params: {
          path: { user_id: userId },
        },
        body: stateUpdate,
      });

      if (error) {
        throw new ApiError(500, error.error || 'Failed to update user state');
      }
      return data;
    },
    onSuccess: (_, { userId }) => {
      // Invalidate related queries
      queryClient.invalidateQueries({ queryKey: ['admin', 'users'] });
      queryClient.invalidateQueries({ queryKey: ['admin', 'users', userId] });
      queryClient.invalidateQueries({ queryKey: ['admin', 'audit-logs'] });
    },
  });
}

/**
 * Hook for batch user operations (enable/disable multiple users)
 */
export function useBatchUpdateUsers(token?: string) {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: async ({
      userIds,
      stateUpdate,
    }: {
      userIds: number[];
      stateUpdate: UpdateUserStateRequest;
    }) => {
      if (!token) {
        throw new Error('No token provided');
      }

      setAuthToken(token);

      // Execute updates in parallel
      const results = await Promise.allSettled(
        userIds.map((userId) =>
          apiClient.PUT('/api/admin/users/{user_id}/state', {
            params: { path: { user_id: userId } },
            body: stateUpdate,
          })
        )
      );

      // Check for any failures
      const failures = results.filter((result) => {
        if (result.status === 'rejected') return true;
        if (result.status === 'fulfilled' && result.value.error) return true;
        return false;
      });

      if (failures.length > 0) {
        throw new ApiError(500, `Failed to update ${failures.length} of ${userIds.length} users`);
      }

      return results;
    },
    onSuccess: () => {
      // Invalidate all user-related queries
      queryClient.invalidateQueries({ queryKey: ['admin', 'users'] });
      queryClient.invalidateQueries({ queryKey: ['admin', 'audit-logs'] });
    },
  });
}
