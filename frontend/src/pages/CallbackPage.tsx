import { useEffect, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { useAuth } from '../hooks/useAuth';
import { useExchangeToken } from '../hooks/api/auth';
import { ApiError } from '../lib/api-client';
import { CheckCircle, XCircle, Loader2 } from 'lucide-react';
import { authLogger } from '../utils/logger';

export function CallbackPage() {
  const { provider } = useParams<{ provider: string }>();
  const navigate = useNavigate();
  const { setTokens, isAuthenticated } = useAuth();
  const exchangeTokenMutation = useExchangeToken();

  const [status, setStatus] = useState<'loading' | 'success' | 'error'>('loading');
  const [error, setError] = useState<string | null>(null);
  const [actualProvider, setActualProvider] = useState<string | null>(provider || null);
  const [shouldNavigate, setShouldNavigate] = useState(false);

  // Monitor authentication state and navigate when ready
  useEffect(() => {
    if (shouldNavigate && isAuthenticated && status === 'success') {
      authLogger.debug('Auth state updated, navigating to dashboard');
      setTimeout(() => {
        navigate('/dashboard', { replace: true });
      }, 1000);
    }
  }, [shouldNavigate, isAuthenticated, status, navigate]);

  useEffect(() => {
    const handleCallback = async () => {
      try {
        authLogger.debug('Starting handleCallback');
        // Extract query parameters from URL
        const urlParams = new URLSearchParams(window.location.search);
        const success = urlParams.get('success');
        const accessToken = urlParams.get('access_token');
        const expiresIn = urlParams.get('expires_in');
        const scope = urlParams.get('scope');
        const urlProvider = urlParams.get('provider');
        const errorParam = urlParams.get('error');
        const errorDescription = urlParams.get('error_description');

        authLogger.debug('URL params', {
          success,
          accessToken: accessToken ? `${accessToken.substring(0, 20)}...` : null,
          expiresIn,
          scope,
          urlProvider,
          errorParam,
          errorDescription,
        });

        // Check for OAuth errors first
        if (errorParam) {
          const errorMsg = errorDescription || errorParam;
          setError(`OAuth error: ${errorMsg}`);
          setStatus('error');
          return;
        }

        // Handle direct success from backend redirect
        if (success === 'true' && accessToken && expiresIn && urlProvider) {
          authLogger.debug('Direct success flow detected');
          // Update the actual provider for display
          setActualProvider(urlProvider);

          // Create token response object from URL parameters
          const tokenResponse = {
            access_token: accessToken,
            token_type: 'Bearer',
            expires_in: parseInt(expiresIn, 10),
            refresh_token: '', // Empty refresh token as per new design
            scope: scope || '',
          };

          authLogger.debug('Calling setTokens', {
            provider: urlProvider,
            tokenType: tokenResponse.token_type,
            expiresIn: tokenResponse.expires_in,
          });

          // Store tokens in auth state and set up navigation
          setTokens(tokenResponse, urlProvider);
          setStatus('success');
          setShouldNavigate(true);
          authLogger.debug('Set up for navigation, waiting for auth state update');
          return;
        }

        // Fallback to old token exchange flow for backward compatibility
        if (!provider) {
          setError('Missing provider parameter');
          setStatus('error');
          return;
        }

        const code = urlParams.get('code');
        const state = urlParams.get('state');

        // Check for required parameters for token exchange
        if (!code) {
          setError('Missing authorization code');
          setStatus('error');
          return;
        }

        if (!state) {
          setError('Missing state parameter');
          setStatus('error');
          return;
        }

        // Build redirect URI (should match what was sent to the OAuth provider)
        const redirectUri = `${window.location.origin}/auth/callback/${provider}`;

        // Exchange code for token
        const tokenResponse = await exchangeTokenMutation.mutateAsync({
          provider,
          authorization_code: code,
          redirect_uri: redirectUri,
          state,
        });

        // Store tokens in auth state and set up navigation
        setTokens(tokenResponse, provider);
        setStatus('success');
        setShouldNavigate(true);
        authLogger.debug('Set up for navigation, waiting for auth state update');
      } catch (err) {
        console.error('Token exchange failed:', err);

        let errorMessage = 'Authentication failed';
        if (err instanceof ApiError) {
          if (err.status === 400) {
            errorMessage = 'Invalid authorization code or state';
          } else if (err.status === 401) {
            errorMessage = 'Authentication was denied';
          } else if (err.status === 500) {
            errorMessage = 'Server error - please try again';
          } else {
            errorMessage = `Error ${err.status}: ${err.message}`;
          }
        } else if (err instanceof Error) {
          errorMessage = err.message;
        }

        setError(errorMessage);
        setStatus('error');
      }
    };

    handleCallback();
  }, [provider, setTokens, navigate, exchangeTokenMutation]);

  const getProviderDisplayName = (provider: string) => {
    const names: { [key: string]: string } = {
      google: 'Google',
      github: 'GitHub',
      microsoft: 'Microsoft',
      gitlab: 'GitLab',
      auth0: 'Auth0',
      okta: 'Okta',
    };
    return names[provider] || provider;
  };

  const handleRetry = () => {
    navigate('/login', { replace: true });
  };

  const handleGoToDashboard = () => {
    navigate('/dashboard', { replace: true });
  };

  if (status === 'loading') {
    return (
      <div className="container">
        <div className="card">
          <div style={{ textAlign: 'center' }}>
            <Loader2
              size={48}
              style={{ color: '#667eea', marginBottom: '1rem' }}
              className="loading-spinner"
            />
            <h2>Processing Authentication</h2>
            <p>
              Exchanging authorization code with{' '}
              {actualProvider ? getProviderDisplayName(actualProvider) : 'OAuth provider'}...
            </p>
            <p style={{ color: '#666', fontSize: '0.875rem', marginTop: '1.5rem' }}>
              This should only take a few seconds. Please don&apos;t close this tab.
            </p>
          </div>
        </div>
      </div>
    );
  }

  if (status === 'success') {
    return (
      <div className="container">
        <div className="card">
          <div style={{ textAlign: 'center' }}>
            <CheckCircle size={48} style={{ color: '#28a745', marginBottom: '1rem' }} />
            <h2
              className="status-message success"
              style={{ border: 'none', background: 'none', color: '#28a745' }}
            >
              ✅ Authentication Successful!
            </h2>
            <p>
              You have successfully authenticated with{' '}
              {actualProvider ? getProviderDisplayName(actualProvider) : 'your OAuth provider'}.
            </p>
            <p style={{ color: '#666', marginBottom: '1.5rem' }}>
              You will be redirected to your dashboard automatically...
            </p>
            <button onClick={handleGoToDashboard} className="btn btn-primary">
              Go to Dashboard
            </button>
          </div>
        </div>
      </div>
    );
  }

  if (status === 'error') {
    return (
      <div className="container">
        <div className="card">
          <div style={{ textAlign: 'center' }}>
            <XCircle size={48} style={{ color: '#dc3545', marginBottom: '1rem' }} />
            <h2
              className="status-message error"
              style={{ border: 'none', background: 'none', color: '#dc3545' }}
            >
              ❌ Authentication Failed
            </h2>
            <p style={{ marginBottom: '1rem' }}>
              <strong>Provider:</strong>{' '}
              {actualProvider ? getProviderDisplayName(actualProvider) : 'Unknown'}
            </p>

            <div className="status-message error">
              <strong>Error Details:</strong>
              <br />
              {error}
            </div>

            <div style={{ marginTop: '2rem' }}>
              <h4>Possible Solutions:</h4>
              <ul style={{ textAlign: 'left', margin: '1rem 0', color: '#666' }}>
                <li>Check that the OAuth provider is properly configured</li>
                <li>Verify the redirect URI matches the configuration</li>
                <li>Ensure you completed the authorization process</li>
                <li>Try logging in again</li>
              </ul>
            </div>

            <div
              style={{
                display: 'flex',
                gap: '1rem',
                justifyContent: 'center',
                flexWrap: 'wrap',
                marginTop: '2rem',
              }}
            >
              <button onClick={handleRetry} className="btn btn-primary">
                Try Again
              </button>
              <button onClick={() => window.history.back()} className="btn btn-secondary">
                Go Back
              </button>
            </div>
          </div>
        </div>
      </div>
    );
  }

  return null;
}
