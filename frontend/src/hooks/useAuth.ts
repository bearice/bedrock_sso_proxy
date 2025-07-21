import { useState, useEffect, useCallback } from 'react';
import { AuthState, TokenResponse } from '../types/auth';
import { authApi } from '../services/api';

const STORAGE_KEY = 'bedrock_auth';

// Parse JWT payload to get expiration
function parseJwtPayload(token: string): any {
  try {
    const payload = token.split('.')[1];
    const decoded = atob(payload);
    return JSON.parse(decoded);
  } catch {
    return null;
  }
}

export function useAuth() {
  const [authState, setAuthState] = useState<AuthState>({
    isAuthenticated: false,
    token: null,
    refreshToken: null,
    provider: null,
    user: null,
    expiresAt: null,
    scopes: [],
  });

  const [loading, setLoading] = useState(true);

  // Load authentication state from localStorage
  useEffect(() => {
    const loadAuthState = async () => {
      try {
        const stored = localStorage.getItem(STORAGE_KEY);
        if (!stored) {
          setLoading(false);
          return;
        }

        const parsed = JSON.parse(stored) as AuthState;
        
        // Check if token is expired
        const now = Date.now() / 1000;
        if (parsed.expiresAt && parsed.expiresAt < now) {
          // Try to refresh token
          if (parsed.refreshToken) {
            try {
              await refreshTokens(parsed.refreshToken);
            } catch (error) {
              console.error('Failed to refresh token:', error);
              clearAuth();
            }
          } else {
            clearAuth();
          }
        } else {
          // Validate stored token
          if (parsed.token) {
            try {
              const validation = await authApi.validateToken(parsed.token);
              if (validation.valid) {
                setAuthState(parsed);
              } else {
                clearAuth();
              }
            } catch (error) {
              console.error('Token validation failed:', error);
              clearAuth();
            }
          }
        }
      } catch (error) {
        console.error('Failed to load auth state:', error);
        clearAuth();
      } finally {
        setLoading(false);
      }
    };

    loadAuthState();
  }, []);

  const saveAuthState = useCallback((state: AuthState) => {
    setAuthState(state);
    if (state.isAuthenticated) {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(state));
    } else {
      localStorage.removeItem(STORAGE_KEY);
    }
  }, []);

  const setTokens = useCallback((
    tokenResponse: TokenResponse,
    provider: string
  ) => {
    const payload = parseJwtPayload(tokenResponse.access_token);
    
    const newAuthState: AuthState = {
      isAuthenticated: true,
      token: tokenResponse.access_token,
      refreshToken: tokenResponse.refresh_token,
      provider,
      user: payload?.sub || null,
      expiresAt: payload?.exp || null,
      scopes: payload?.scopes || tokenResponse.scope.split(' '),
    };

    saveAuthState(newAuthState);
  }, [saveAuthState]);

  const refreshTokens = useCallback(async (refreshToken: string) => {
    try {
      const response = await authApi.refreshToken({ refresh_token: refreshToken });
      const payload = parseJwtPayload(response.access_token);
      
      const newAuthState: AuthState = {
        ...authState,
        isAuthenticated: true,
        token: response.access_token,
        refreshToken: response.refresh_token,
        expiresAt: payload?.exp || null,
        scopes: payload?.scopes || response.scope.split(' '),
      };

      saveAuthState(newAuthState);
      return response;
    } catch (error) {
      clearAuth();
      throw error;
    }
  }, [authState, saveAuthState]);

  const clearAuth = useCallback(() => {
    saveAuthState({
      isAuthenticated: false,
      token: null,
      refreshToken: null,
      provider: null,
      user: null,
      expiresAt: null,
      scopes: [],
    });
  }, [saveAuthState]);

  const logout = useCallback(() => {
    clearAuth();
  }, [clearAuth]);

  // Auto refresh token before expiration
  useEffect(() => {
    if (!authState.isAuthenticated || !authState.expiresAt || !authState.refreshToken) {
      return;
    }

    const now = Date.now() / 1000;
    const timeUntilExpiry = authState.expiresAt - now;
    const refreshThreshold = 300; // 5 minutes before expiry

    if (timeUntilExpiry <= refreshThreshold) {
      refreshTokens(authState.refreshToken);
      return;
    }

    // Set up timer to refresh token
    const refreshTimer = setTimeout(() => {
      if (authState.refreshToken) {
        refreshTokens(authState.refreshToken);
      }
    }, (timeUntilExpiry - refreshThreshold) * 1000);

    return () => clearTimeout(refreshTimer);
  }, [authState, refreshTokens]);

  return {
    ...authState,
    loading,
    setTokens,
    refreshTokens,
    logout,
    clearAuth,
  };
}