import {
  ProvidersResponse,
  AuthorizeResponse,
  TokenResponse,
  TokenRequest,
  RefreshRequest,
  CreateApiKeyRequest,
  CreateApiKeyResponse,
  ApiKeyInfo,
} from '../types/auth';
import {
  UsageQuery,
  UsageStatsQuery,
  UsageRecordsResponse,
  UsageStats,
  TopModelsResponse,
} from '../types/usage';

const API_BASE = ''; // Proxied by Vite dev server or served from same origin in production

class ApiError extends Error {
  constructor(
    public status: number,
    message: string
  ) {
    super(message);
    this.name = 'ApiError';
  }
}

async function fetchApi<T>(endpoint: string, options: RequestInit = {}): Promise<T> {
  const response = await fetch(`${API_BASE}${endpoint}`, {
    headers: {
      'Content-Type': 'application/json',
      ...options.headers,
    },
    ...options,
  });

  if (!response.ok) {
    let errorMessage = `HTTP ${response.status}`;
    try {
      const errorData = await response.text();
      errorMessage = errorData || errorMessage;
    } catch {
      // Ignore JSON parsing errors
    }
    throw new ApiError(response.status, errorMessage);
  }

  // Handle empty responses
  if (response.status === 204) {
    return {} as T;
  }

  return response.json();
}

// Helper function to create authenticated requests
function createAuthenticatedRequest(token: string, options: RequestInit = {}): RequestInit {
  return {
    ...options,
    headers: {
      Authorization: `Bearer ${token}`,
      ...options.headers,
    },
  };
}

export const authApi = {
  // Get list of available OAuth providers
  async getProviders(): Promise<ProvidersResponse> {
    return fetchApi<ProvidersResponse>('/auth/providers');
  },

  // Get authorization URL for OAuth provider
  async getAuthorizationUrl(provider: string, redirectUri?: string): Promise<AuthorizeResponse> {
    const params = new URLSearchParams();
    if (redirectUri) {
      params.append('redirect_uri', redirectUri);
    }

    const query = params.toString() ? `?${params.toString()}` : '';
    return fetchApi<AuthorizeResponse>(`/auth/authorize/${provider}${query}`);
  },

  // Exchange authorization code for JWT token
  async exchangeToken(request: TokenRequest): Promise<TokenResponse> {
    return fetchApi<TokenResponse>('/auth/token', {
      method: 'POST',
      body: JSON.stringify(request),
    });
  },

  // Refresh JWT token
  async refreshToken(request: RefreshRequest): Promise<TokenResponse> {
    return fetchApi<TokenResponse>('/auth/refresh', {
      method: 'POST',
      body: JSON.stringify(request),
    });
  },

  // Health check
  async healthCheck(): Promise<{ status: string }> {
    return fetchApi<{ status: string }>('/health');
  },
};

export const apiKeyApi = {
  // Create a new API key
  async createApiKey(token: string, request: CreateApiKeyRequest): Promise<CreateApiKeyResponse> {
    return fetchApi<CreateApiKeyResponse>('/api/keys', {
      method: 'POST',
      body: JSON.stringify(request),
      ...createAuthenticatedRequest(token),
    });
  },

  // List all API keys for the authenticated user
  async listApiKeys(token: string): Promise<ApiKeyInfo[]> {
    return fetchApi<ApiKeyInfo[]>('/api/keys', createAuthenticatedRequest(token));
  },

  // Revoke an API key
  async revokeApiKey(token: string, keyId: string): Promise<{ message: string; key: string }> {
    return fetchApi<{ message: string; key: string }>(`/api/keys/${keyId}`, {
      method: 'DELETE',
      ...createAuthenticatedRequest(token),
    });
  },
};

export const usageApi = {
  // Get user's usage records
  async getUserUsageRecords(token: string, query?: UsageQuery): Promise<UsageRecordsResponse> {
    const params = new URLSearchParams();
    if (query?.limit) params.append('limit', query.limit.toString());
    if (query?.offset) params.append('offset', query.offset.toString());
    if (query?.model) params.append('model', query.model);
    if (query?.start_date) params.append('start_date', query.start_date);
    if (query?.end_date) params.append('end_date', query.end_date);
    if (query?.success_only !== undefined)
      params.append('success_only', query.success_only.toString());

    const queryString = params.toString() ? `?${params.toString()}` : '';
    return fetchApi<UsageRecordsResponse>(
      `/api/usage/records${queryString}`,
      createAuthenticatedRequest(token)
    );
  },

  // Get user's usage statistics
  async getUserUsageStats(token: string, query?: UsageStatsQuery): Promise<UsageStats> {
    const params = new URLSearchParams();
    if (query?.start_date) params.append('start_date', query.start_date);
    if (query?.end_date) params.append('end_date', query.end_date);

    const queryString = params.toString() ? `?${params.toString()}` : '';
    return fetchApi<UsageStats>(
      `/api/usage/stats${queryString}`,
      createAuthenticatedRequest(token)
    );
  },

  // Admin endpoints (for future use)
  async getSystemUsageRecords(token: string, query?: UsageQuery): Promise<UsageRecordsResponse> {
    const params = new URLSearchParams();
    if (query?.limit) params.append('limit', query.limit.toString());
    if (query?.offset) params.append('offset', query.offset.toString());
    if (query?.model) params.append('model', query.model);
    if (query?.start_date) params.append('start_date', query.start_date);
    if (query?.end_date) params.append('end_date', query.end_date);
    if (query?.success_only !== undefined)
      params.append('success_only', query.success_only.toString());

    const queryString = params.toString() ? `?${params.toString()}` : '';
    return fetchApi<UsageRecordsResponse>(
      `/api/admin/usage/records${queryString}`,
      createAuthenticatedRequest(token)
    );
  },

  async getSystemUsageStats(token: string, query?: UsageStatsQuery): Promise<UsageStats> {
    const params = new URLSearchParams();
    if (query?.start_date) params.append('start_date', query.start_date);
    if (query?.end_date) params.append('end_date', query.end_date);

    const queryString = params.toString() ? `?${params.toString()}` : '';
    return fetchApi<UsageStats>(
      `/api/admin/usage/stats${queryString}`,
      createAuthenticatedRequest(token)
    );
  },

  async getTopModels(token: string, query?: UsageStatsQuery): Promise<TopModelsResponse> {
    const params = new URLSearchParams();
    if (query?.start_date) params.append('start_date', query.start_date);
    if (query?.end_date) params.append('end_date', query.end_date);

    const queryString = params.toString() ? `?${params.toString()}` : '';
    return fetchApi<TopModelsResponse>(
      `/api/admin/usage/top-models${queryString}`,
      createAuthenticatedRequest(token)
    );
  },

  // Convenience methods with new names for backward compatibility
  async getUsageRecords(token: string, query?: UsageQuery): Promise<UsageRecordsResponse> {
    return this.getUserUsageRecords(token, query);
  },

  async getUsageStats(token: string, query?: UsageStatsQuery): Promise<UsageStats> {
    return this.getUserUsageStats(token, query);
  },

  async getAvailableModels(_token: string): Promise<string[]> {
    // For now, return common model IDs - in a real implementation this would be an API call
    return [
      'anthropic.claude-3-haiku-20240307-v1:0',
      'anthropic.claude-3-sonnet-20240229-v1:0',
      'anthropic.claude-3-opus-20240229-v1:0',
      'anthropic.claude-sonnet-4-20250514-v1:0',
    ];
  },

  async exportUsageData(
    token: string,
    query: {
      start_date?: string;
      end_date?: string;
      model?: string;
      success?: boolean;
      format: 'csv';
    }
  ): Promise<Blob> {
    const params = new URLSearchParams();
    if (query.start_date) params.append('start_date', query.start_date);
    if (query.end_date) params.append('end_date', query.end_date);
    if (query.model) params.append('model', query.model);
    if (query.success !== undefined) params.append('success', query.success.toString());
    params.append('format', query.format);

    const queryString = params.toString() ? `?${params.toString()}` : '';
    const response = await fetch(`${API_BASE}/api/usage/export${queryString}`, {
      ...createAuthenticatedRequest(token),
    });

    if (!response.ok) {
      throw new ApiError(response.status, `Export failed: ${response.statusText}`);
    }

    return response.blob();
  },
};

export { ApiError };
