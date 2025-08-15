import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { apiClient, ApiError } from '../../../lib/api-client';
import type { components } from '../../../generated/api';

// Type aliases for better readability
type ModelCost = components['schemas']['ModelCost'];
type ModelCostRequest = components['schemas']['ModelCostRequest'];
type UpdateCostsResult = components['schemas']['UpdateCostsResult'];

// ============================================================================
// MODEL COST MANAGEMENT HOOKS
// ============================================================================

/**
 * Get all model costs (admin only)
 */
export function useAdminModelCosts(token?: string) {
  return useQuery({
    queryKey: ['admin', 'costs', token],
    queryFn: async (): Promise<ModelCost[]> => {
      if (!token) {
        throw new Error('No token provided');
      }

      const { data, error } = await apiClient.GET('/api/admin/costs', {
        headers: {
          Authorization: `Bearer ${token}`,
        },
      });

      if (error) {
        throw new ApiError(500, error.error || 'Failed to fetch model costs');
      }
      return data as ModelCost[];
    },
    enabled: !!token,
  });
}

/**
 * Get specific model cost by region and model ID (admin only)
 */
export function useAdminModelCost(token?: string, region?: string, modelId?: string) {
  return useQuery({
    queryKey: ['admin', 'costs', region, modelId, token],
    queryFn: async (): Promise<ModelCost> => {
      if (!token || !region || !modelId) {
        throw new Error('No token, region, or model ID provided');
      }

      const { data, error } = await apiClient.GET('/api/admin/costs/{region}/{model_id}', {
        params: {
          path: { region, model_id: modelId },
        },
        headers: {
          Authorization: `Bearer ${token}`,
        },
      });

      if (error) {
        throw new ApiError(500, error.error || 'Failed to fetch model cost');
      }
      return data as ModelCost;
    },
    enabled: !!token && !!region && !!modelId,
  });
}

/**
 * Update/create model cost (admin only)
 */
export function useUpdateModelCost(token?: string) {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: async ({
      region,
      modelId,
      costData,
    }: {
      region: string;
      modelId: string;
      costData: ModelCostRequest;
    }) => {
      if (!token) {
        throw new Error('No token provided');
      }

      const { data, error } = await apiClient.PUT('/api/admin/costs/{region}/{model_id}', {
        params: {
          path: { region, model_id: modelId },
        },
        body: costData,
        headers: {
          Authorization: `Bearer ${token}`,
        },
      });

      if (error) {
        throw new ApiError(500, error.error || 'Failed to update model cost');
      }
      return data;
    },
    onSuccess: (_, { region, modelId }) => {
      // Invalidate related queries
      queryClient.invalidateQueries({ queryKey: ['admin', 'costs'] });
      queryClient.invalidateQueries({ queryKey: ['admin', 'costs', region, modelId] });
    },
  });
}

/**
 * Delete model cost (admin only)
 */
export function useDeleteModelCost(token?: string) {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: async ({ region, modelId }: { region: string; modelId: string }) => {
      if (!token) {
        throw new Error('No token provided');
      }

      const { error } = await apiClient.DELETE('/api/admin/costs/{region}/{model_id}', {
        params: {
          path: { region, model_id: modelId },
        },
        headers: {
          Authorization: `Bearer ${token}`,
        },
      });

      if (error) {
        throw new ApiError(500, error.error || 'Failed to delete model cost');
      }
    },
    onSuccess: (_, { region, modelId }) => {
      // Invalidate related queries
      queryClient.invalidateQueries({ queryKey: ['admin', 'costs'] });
      queryClient.invalidateQueries({ queryKey: ['admin', 'costs', region, modelId] });
    },
  });
}

/**
 * Bulk update model costs via CSV (admin only)
 */
export function useBulkUpdateModelCosts(token?: string) {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: async (csvContent: string): Promise<UpdateCostsResult> => {
      if (!token) {
        throw new Error('No token provided');
      }

      const { data, error } = await apiClient.POST('/api/admin/costs', {
        body: csvContent,
        headers: {
          Authorization: `Bearer ${token}`,
        },
      });

      if (error) {
        throw new ApiError(500, error.error || 'Failed to bulk update model costs');
      }
      return data as UpdateCostsResult;
    },
    onSuccess: () => {
      // Invalidate all cost queries
      queryClient.invalidateQueries({ queryKey: ['admin', 'costs'] });
    },
  });
}
