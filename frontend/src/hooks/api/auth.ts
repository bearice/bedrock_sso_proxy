import { useMutation, useQuery } from '@tanstack/react-query';
import { apiClient, ApiError } from '../../lib/api-client';
import type { components } from '../../generated/api';

// Type aliases for generated types
type ProvidersResponse = components['schemas']['ProvidersResponse'];
type AuthorizeResponse = components['schemas']['AuthorizeResponse'];
type TokenResponse = components['schemas']['TokenResponse'];
type TokenRequest = components['schemas']['TokenRequest'];
type RefreshRequest = components['schemas']['RefreshRequest'];
type UserInfo = components['schemas']['Model']; // The /auth/me endpoint returns Model schema
type HealthResponse = components['schemas']['HealthResponse'];

// Get available OAuth providers
export function useProviders() {
  return useQuery({
    queryKey: ['auth', 'providers'],
    queryFn: async (): Promise<ProvidersResponse> => {
      const { data, error } = await apiClient.GET('/auth/providers');
      if (error) {
        throw new ApiError(500, error.error || 'Failed to fetch providers');
      }
      return data as ProvidersResponse;
    },
  });
}

// Get authorization URL for OAuth provider
export function useAuthorizationUrl() {
  return useMutation({
    mutationFn: async (provider: string): Promise<AuthorizeResponse> => {
      const { data, error } = await apiClient.GET('/auth/authorize/{provider}', {
        params: {
          path: { provider },
        },
      });
      if (error) {
        throw new ApiError(500, error.error || 'Failed to get authorization URL');
      }
      return data as AuthorizeResponse;
    },
  });
}

// Exchange authorization code for JWT token
export function useExchangeToken() {
  return useMutation({
    mutationFn: async (request: TokenRequest): Promise<TokenResponse> => {
      const { data, error } = await apiClient.POST('/auth/token', {
        body: request,
      });
      if (error) {
        throw new ApiError(500, error.error || 'Failed to exchange token');
      }
      return data as TokenResponse;
    },
  });
}

// Refresh JWT token
export function useRefreshToken() {
  return useMutation({
    mutationFn: async (request: RefreshRequest): Promise<TokenResponse> => {
      const { data, error } = await apiClient.POST('/auth/refresh', {
        body: request,
      });
      if (error) {
        throw new ApiError(500, error.error || 'Failed to refresh token');
      }
      return data as TokenResponse;
    },
  });
}

// Health check
export function useHealthCheck() {
  return useQuery({
    queryKey: ['health'],
    queryFn: async (): Promise<HealthResponse> => {
      const { data, error } = await apiClient.GET('/health');
      if (error) {
        throw new ApiError(500, error.error || 'Health check failed');
      }
      return data as HealthResponse;
    },
    refetchInterval: 30000, // Check every 30 seconds
  });
}

// Get current user info (requires JWT authentication)
export function useCurrentUser(token?: string) {
  return useQuery({
    queryKey: ['auth', 'me', token],
    queryFn: async (): Promise<UserInfo> => {
      if (!token) {
        throw new Error('No token provided');
      }

      const { data, error } = await apiClient.GET('/auth/me', {
        headers: {
          Authorization: `Bearer ${token}`,
        },
      });
      if (error) {
        throw new ApiError(500, error.error || 'Failed to get user info');
      }
      return data as UserInfo;
    },
    enabled: !!token,
    retry: false, // Don't retry auth failures
  });
}

// Validate token helper
export function useValidateToken(token?: string) {
  return useQuery({
    queryKey: ['auth', 'validate', token],
    queryFn: async (): Promise<UserInfo | null> => {
      if (!token) return null;

      try {
        const { data, error } = await apiClient.GET('/auth/me', {
          headers: {
            Authorization: `Bearer ${token}`,
          },
        });
        if (error) {
          return null; // Token is invalid
        }
        return data as UserInfo;
      } catch {
        return null; // Token validation failed
      }
    },
    enabled: !!token,
    retry: false,
    refetchOnMount: false,
  });
}
