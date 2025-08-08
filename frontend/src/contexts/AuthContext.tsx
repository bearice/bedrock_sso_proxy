import React, { createContext, useState, useEffect, useLayoutEffect, useCallback } from 'react';
import type { components } from '../generated/api';
import { useRefreshToken } from '../hooks/api';
import { setAuthToken, clearAuthToken } from '../lib/api-client';

type TokenResponse = components['schemas']['TokenResponse'];

// Custom AuthState interface for local state management
interface AuthState {
  isAuthenticated: boolean;
  token: string | null;
  refreshToken: string | null;
  provider: string | null;
  user: string | null;
  expiresAt: number | null;
  scopes: string[];
  isAdmin: boolean;
}

const STORAGE_KEY = 'bedrock_auth';

// Parse JWT payload to get expiration and user info
function parseJwtPayload(
  token: string
): {
  sub?: string;
  exp?: number;
  scopes?: string[];
  email?: string;
  provider?: string;
  admin?: boolean;
} | null {
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
    isAdmin: false,
  });

  const [loading, setLoading] = useState(true);
  const refreshTokenMutation = useRefreshToken();

  const saveAuthState = useCallback((state: AuthState) => {
    setAuthState(state);
    if (state.isAuthenticated) {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(state));
    } else {
      localStorage.removeItem(STORAGE_KEY);
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
      isAdmin: false,
    });
  }, [saveAuthState]);

  const refreshTokens = useCallback(
    async (refreshToken: string) => {
      try {
        const response = await refreshTokenMutation.mutateAsync({ refresh_token: refreshToken });
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
            isAdmin: payload?.admin || false,
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
    [clearAuth, refreshTokenMutation]
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
              const response = await refreshTokenMutation.mutateAsync({
                refresh_token: parsed.refreshToken,
              });
              const payload = parseJwtPayload(response.access_token);

              const newAuthState: AuthState = {
                ...parsed,
                isAuthenticated: true,
                token: response.access_token,
                refreshToken: response.refresh_token,
                expiresAt: payload?.exp || null,
                scopes: payload?.scopes || response.scope.split(' '),
                isAdmin: payload?.admin || false,
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
                isAdmin: false,
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
              isAdmin: false,
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
          isAdmin: false,
        });
        localStorage.removeItem(STORAGE_KEY);
      } finally {
        setLoading(false);
      }
    };

    loadAuthState();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []); // Run only once on mount

  const setTokens = useCallback(
    (tokenResponse: TokenResponse, provider: string) => {
      const payload = parseJwtPayload(tokenResponse.access_token);

      const newAuthState: AuthState = {
        isAuthenticated: true,
        token: tokenResponse.access_token,
        refreshToken: tokenResponse.refresh_token,
        provider,
        user: payload?.email || payload?.sub || null,
        expiresAt: payload?.exp || null,
        scopes: payload?.scopes || tokenResponse.scope.split(' '),
        isAdmin: payload?.admin || false,
      };

      saveAuthState(newAuthState);
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

  // Set auth token on API client whenever auth state changes
  // Use useLayoutEffect to ensure this runs before DOM updates and component renders
  useLayoutEffect(() => {
    if (authState.isAuthenticated && authState.token) {
      setAuthToken(authState.token);
    } else if (!loading) {
      // Only clear token if we're not in the initial loading state
      clearAuthToken();
    }
  }, [authState.isAuthenticated, authState.token, loading]);

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
