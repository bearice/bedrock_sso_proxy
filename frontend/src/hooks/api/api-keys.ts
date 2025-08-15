import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { apiClient, ApiError } from '../../lib/api-client';
import type { components } from '../../generated/api';

// Type aliases for better readability
type ApiKey = components['schemas']['ApiKey'];
type CreateApiKeyRequest = components['schemas']['CreateApiKeyRequest'];
type CreateApiKeyResponse = components['schemas']['CreateApiKeyResponse'];

// List all API keys for the authenticated user
export function useApiKeys() {
  return useQuery({
    queryKey: ['api-keys'],
    queryFn: async (): Promise<ApiKey[]> => {
      const { data, error } = await apiClient.GET('/api/keys');

      if (error) {
        throw new ApiError(500, error.error || 'Failed to fetch API keys');
      }
      return data as ApiKey[];
    },
  });
}

// Create a new API key
export function useCreateApiKey() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: async (request: CreateApiKeyRequest): Promise<CreateApiKeyResponse> => {
      const { data, error } = await apiClient.POST('/api/keys', {
        body: request,
      });

      if (error) {
        throw new ApiError(500, error.error || 'Failed to create API key');
      }
      return data as CreateApiKeyResponse;
    },
    onSuccess: () => {
      // Invalidate and refetch API keys list
      queryClient.invalidateQueries({
        queryKey: ['api-keys'],
      });
    },
  });
}

// Revoke an API key
export function useRevokeApiKey() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: async (keyHash: string): Promise<void> => {
      const { error } = await apiClient.DELETE('/api/keys/{key_hash}', {
        params: {
          path: { key_hash: keyHash },
        },
      });

      if (error) {
        throw new ApiError(500, error.error || 'Failed to revoke API key');
      }
    },
    onSuccess: () => {
      // Invalidate and refetch API keys list
      queryClient.invalidateQueries({
        queryKey: ['api-keys'],
      });
    },
  });
}
