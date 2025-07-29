import React, { createContext, useState, useEffect, useCallback } from 'react';
import { AuthState, TokenResponse } from '../types/auth';
import { authApi } from '../services/api';
import { authLogger } from '../utils/logger';

const STORAGE_KEY = 'bedrock_auth';

// Parse JWT payload to get expiration and user info
function parseJwtPayload(
  token: string
): { sub?: string; exp?: number; scopes?: string[]; email?: string; provider?: string } | null {
  try {
    const payload = token.split('.')[1];
    const decoded = atob(payload);
    return JSON.parse(decoded);
  } catch {
    return null;
  }
}

export interface AuthContextType extends AuthState {
  loading: boolean;
  setTokens: (tokenResponse: TokenResponse, provider: string) => void;
  refreshTokens: (refreshToken: string) => Promise<TokenResponse>;
  logout: () => void;
  clearAuth: () => void;
}

// eslint-disable-next-line react-refresh/only-export-components
export const AuthContext = createContext<AuthContextType | undefined>(undefined);

export function AuthProvider({ children }: { children: React.ReactNode }) {
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

  // Debug log only significant state changes
  useEffect(() => {
    if (authState.isAuthenticated || loading === false) {
      authLogger.debug('State updated', {
        isAuthenticated: authState.isAuthenticated,
        provider: authState.provider,
        loading: loading,
      });
    }
  }, [authState.isAuthenticated, authState.provider, loading]);

  const saveAuthState = useCallback((state: AuthState) => {
    authLogger.debug('saveAuthState called', {
      isAuthenticated: state.isAuthenticated,
      provider: state.provider,
      user: state.user,
    });
    setAuthState(state);
    if (state.isAuthenticated) {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(state));
      authLogger.debug('Saved auth state to localStorage');
    } else {
      localStorage.removeItem(STORAGE_KEY);
      authLogger.debug('Removed auth state from localStorage');
    }
  }, []);

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

  const refreshTokens = useCallback(
    async (refreshToken: string) => {
      try {
        const response = await authApi.refreshToken({ refresh_token: refreshToken });
        const payload = parseJwtPayload(response.access_token);

        // Use functional state update to avoid dependency on authState
        setAuthState((currentAuthState) => {
          const newAuthState: AuthState = {
            ...currentAuthState,
            isAuthenticated: true,
            token: response.access_token,
            refreshToken: response.refresh_token,
            expiresAt: payload?.exp || null,
            scopes: payload?.scopes || response.scope.split(' '),
          };

          // Save to localStorage
          localStorage.setItem(STORAGE_KEY, JSON.stringify(newAuthState));
          return newAuthState;
        });

        return response;
      } catch (error) {
        clearAuth();
        throw error;
      }
    },
    [clearAuth]
  );

  // Load authentication state from localStorage (run only once on mount)
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
              const response = await authApi.refreshToken({ refresh_token: parsed.refreshToken });
              const payload = parseJwtPayload(response.access_token);

              const newAuthState: AuthState = {
                ...parsed,
                isAuthenticated: true,
                token: response.access_token,
                refreshToken: response.refresh_token,
                expiresAt: payload?.exp || null,
                scopes: payload?.scopes || response.scope.split(' '),
              };

              setAuthState(newAuthState);
              localStorage.setItem(STORAGE_KEY, JSON.stringify(newAuthState));
            } catch (error) {
              console.error('Failed to refresh token:', error);
              // Clear auth state on refresh failure
              setAuthState({
                isAuthenticated: false,
                token: null,
                refreshToken: null,
                provider: null,
                user: null,
                expiresAt: null,
                scopes: [],
              });
              localStorage.removeItem(STORAGE_KEY);
            }
          } else {
            // No refresh token, clear auth state
            setAuthState({
              isAuthenticated: false,
              token: null,
              refreshToken: null,
              provider: null,
              user: null,
              expiresAt: null,
              scopes: [],
            });
            localStorage.removeItem(STORAGE_KEY);
          }
        } else {
          // Trust stored tokens without validation - they come from successful OAuth flow
          setAuthState(parsed);
        }
      } catch (error) {
        console.error('Failed to load auth state:', error);
        // Clear auth state on error
        setAuthState({
          isAuthenticated: false,
          token: null,
          refreshToken: null,
          provider: null,
          user: null,
          expiresAt: null,
          scopes: [],
        });
        localStorage.removeItem(STORAGE_KEY);
      } finally {
        setLoading(false);
      }
    };

    loadAuthState();
  }, []); // Empty dependency array - run only once on mount

  const setTokens = useCallback(
    (tokenResponse: TokenResponse, provider: string) => {
      authLogger.debug('setTokens called', { provider });
      const payload = parseJwtPayload(tokenResponse.access_token);
      authLogger.debug('JWT payload parsed', payload);

      const newAuthState: AuthState = {
        isAuthenticated: true,
        token: tokenResponse.access_token,
        refreshToken: tokenResponse.refresh_token,
        provider,
        user: payload?.email || payload?.sub || null,
        expiresAt: payload?.exp || null,
        scopes: payload?.scopes || tokenResponse.scope.split(' '),
      };

      authLogger.debug('New auth state created', {
        isAuthenticated: newAuthState.isAuthenticated,
        provider: newAuthState.provider,
        user: newAuthState.user,
        hasToken: !!newAuthState.token,
        tokenLength: newAuthState.token?.length,
      });

      saveAuthState(newAuthState);
      authLogger.info('Authentication successful', { provider, user: newAuthState.user });
    },
    [saveAuthState]
  );

  const logout = useCallback(() => {
    clearAuth();
    // Force navigation to login page
    window.location.href = '/login';
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
    const refreshTimer = setTimeout(
      () => {
        if (authState.refreshToken) {
          refreshTokens(authState.refreshToken);
        }
      },
      (timeUntilExpiry - refreshThreshold) * 1000
    );

    return () => clearTimeout(refreshTimer);
  }, [authState, refreshTokens]);

  const contextValue: AuthContextType = {
    ...authState,
    loading,
    setTokens,
    refreshTokens,
    logout,
    clearAuth,
  };

  return <AuthContext.Provider value={contextValue}>{children}</AuthContext.Provider>;
}
