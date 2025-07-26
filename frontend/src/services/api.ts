import {
  ProvidersResponse,
  AuthorizeResponse,
  TokenResponse,
  TokenRequest,
  RefreshRequest,
} from '../types/auth';

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

export { ApiError };
