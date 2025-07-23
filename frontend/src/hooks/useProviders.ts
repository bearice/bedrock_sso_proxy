import { useState, useEffect } from 'react';
import { OAuthProvider } from '../types/auth';
import { authApi, ApiError } from '../services/api';

export function useProviders() {
  const [providers, setProviders] = useState<OAuthProvider[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const loadProviders = async () => {
      try {
        setLoading(true);
        setError(null);

        const response = await authApi.getProviders();
        setProviders(response.providers);
      } catch (err) {
        let errorMessage = 'Failed to load OAuth providers';

        if (err instanceof ApiError) {
          if (err.status === 500) {
            errorMessage = 'Server error - please check OAuth configuration';
          } else if (err.status >= 400) {
            errorMessage = `OAuth service error: ${err.message}`;
          }
        } else if (err instanceof Error) {
          errorMessage = err.message;
        }

        console.error('Failed to load providers:', err);
        setError(errorMessage);
      } finally {
        setLoading(false);
      }
    };

    loadProviders();
  }, []);

  const refreshProviders = () => {
    const loadProviders = async () => {
      try {
        setError(null);
        const response = await authApi.getProviders();
        setProviders(response.providers);
      } catch (err) {
        console.error('Failed to refresh providers:', err);
        setError('Failed to refresh providers');
      }
    };

    loadProviders();
  };

  return {
    providers,
    loading,
    error,
    refreshProviders,
  };
}
