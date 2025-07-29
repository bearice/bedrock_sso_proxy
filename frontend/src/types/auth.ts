export interface OAuthProvider {
  name: string;
  display_name: string;
  scopes: string[];
}

export interface ProvidersResponse {
  providers: OAuthProvider[];
}

export interface AuthorizeResponse {
  authorization_url: string;
  state: string;
  provider: string;
}

export interface TokenResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
  refresh_token: string;
  scope: string;
}

export interface TokenRequest {
  provider: string;
  authorization_code: string;
  redirect_uri: string;
  state: string;
}

export interface RefreshRequest {
  refresh_token: string;
}

export interface AuthState {
  isAuthenticated: boolean;
  token: string | null;
  refreshToken: string | null;
  provider: string | null;
  user: string | null;
  expiresAt: number | null;
  scopes: string[];
}

// API Key Management Types
export interface CreateApiKeyRequest {
  name: string;
  expires_in_days?: number;
}

export interface CreateApiKeyResponse {
  id: number;
  name: string;
  key: string;
  created_at: string;
  expires_at?: string;
}

export interface ApiKeyInfo {
  id: number;
  name: string;
  key_hash: string;
  hint: string;
  created_at: string;
  expires_at?: string;
  revoked_at?: string;
}
