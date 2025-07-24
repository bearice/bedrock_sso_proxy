import { useState } from 'react';
import { useProviders } from '../hooks/useProviders';
import { authApi, ApiError } from '../services/api';
import { Shield, RefreshCw, AlertCircle } from 'lucide-react';

const GoogleLogo = () => (
  <svg width="24" height="24" viewBox="0 0 48 48" style={{ marginRight: '8px', background: '#f8f9fa', borderRadius: '4px', padding: '3px' }}>
    <path fill="#FFC107" d="M43.611 20.083H42V20H24v8h11.303c-1.649 4.657-6.08 8-11.303 8-6.627 0-12-5.373-12-12s5.373-12 12-12c3.059 0 5.842 1.154 7.961 3.039l5.657-5.657C34.046 6.053 29.268 4 24 4 12.955 4 4 12.955 4 24s8.955 20 20 20 20-8.955 20-20c0-1.341-.138-2.65-.389-3.917z"/>
    <path fill="#FF3D00" d="M6.306 14.691l6.571 4.819C14.655 15.108 18.961 12 24 12c3.059 0 5.842 1.154 7.961 3.039l5.657-5.657C34.046 6.053 29.268 4 24 4 16.318 4 9.656 8.337 6.306 14.691z"/>
    <path fill="#4CAF50" d="M24 44c5.166 0 9.86-1.977 13.409-5.192l-6.19-5.238C29.211 35.091 26.715 36 24 36c-5.202 0-9.619-3.317-11.283-7.946l-6.522 5.025C9.505 39.556 16.227 44 24 44z"/>
    <path fill="#1976D2" d="M43.611 20.083H42V20H24v8h11.303c-.792 2.237-2.231 4.166-4.087 5.571.001-.001.002-.001.003-.002l6.19 5.238C36.971 39.205 44 34 44 24c0-1.341-.138-2.65-.389-3.917z"/>
  </svg>
);

const GitHubLogo = () => (
  <svg width="24" height="24" viewBox="0 0 24 24" style={{ marginRight: '8px', background: 'white', borderRadius: '4px', padding: '3px' }}>
    <path fill="#181717" d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z"/>
  </svg>
);

const MicrosoftLogo = () => (
  <svg width="24" height="24" viewBox="0 0 24 24" style={{ marginRight: '8px', background: 'white', borderRadius: '4px', padding: '3px' }}>
    <path fill="#F25022" d="M1 1h10v10H1z"/>
    <path fill="#00A4EF" d="M13 1h10v10H13z"/>
    <path fill="#7FBA00" d="M1 13h10v10H1z"/>
    <path fill="#FFB900" d="M13 13h10v10H13z"/>
  </svg>
);

const GitLabLogo = () => (
  <svg width="24" height="24" viewBox="0 0 24 24" style={{ marginRight: '8px', background: 'white', borderRadius: '4px', padding: '3px' }}>
    <path fill="#FC6D26" d="M12 2L8.5 11h7L12 2z"/>
    <path fill="#E24329" d="M12 2L8.5 11H2l10 9 10-9h-6.5L12 2z"/>
    <path fill="#FC6D26" d="M2 11l3.5-9L8.5 11H2z"/>
    <path fill="#FCA326" d="M2 11h6.5L12 20 2 11z"/>
    <path fill="#E24329" d="M12 20l3.5-9H22L12 20z"/>
    <path fill="#FC6D26" d="M22 11l-3.5-9L15.5 11H22z"/>
    <path fill="#FCA326" d="M22 11h-6.5L12 20L22 11z"/>
  </svg>
);

const Auth0Logo = () => (
  <svg width="24" height="24" viewBox="0 0 24 24" style={{ marginRight: '8px', background: 'white', borderRadius: '4px', padding: '3px' }}>
    <path fill="#EB5424" d="M15.99 12.85L12 3.84 8.01 12.85l3.99-1.52 3.99 1.52z"/>
    <path fill="#16214D" d="M8.01 12.85L4.02 21.86l7.98-3.04L8.01 12.85z"/>
    <path fill="#16214D" d="M15.99 12.85l3.99 9.01-7.98-3.04 3.99-6.97z"/>
  </svg>
);

const OktaLogo = () => (
  <svg width="24" height="24" viewBox="0 0 24 24" style={{ marginRight: '8px', background: 'white', borderRadius: '4px', padding: '3px' }}>
    <path fill="#007DC1" d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm0 16c-3.31 0-6-2.69-6-6s2.69-6 6-6 6 2.69 6 6-2.69 6-6 6z"/>
    <circle fill="#007DC1" cx="12" cy="12" r="3"/>
  </svg>
);

const DefaultLogo = () => (
  <svg width="24" height="24" viewBox="0 0 24 24" style={{ marginRight: '8px', background: 'white', borderRadius: '4px', padding: '3px' }}>
    <path fill="#666666" d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4z"/>
    <path fill="#ffffff" d="M12 7c-2.76 0-5 2.24-5 5s2.24 5 5 5 5-2.24 5-5-2.24-5-5-5zm0 8c-1.66 0-3-1.34-3-3s1.34-3 3-3 3 1.34 3 3-1.34 3-3 3z"/>
  </svg>
);

const getProviderIcon = (name: string) => {
  switch (name) {
    case 'google':
      return <GoogleLogo />;
    case 'github':
      return <GitHubLogo />;
    case 'microsoft':
      return <MicrosoftLogo />;
    case 'gitlab':
      return <GitLabLogo />;
    case 'auth0':
      return <Auth0Logo />;
    case 'okta':
      return <OktaLogo />;
    default:
      return <DefaultLogo />;
  }
};

export function LoginPage() {
  const { providers, loading, error, refreshProviders } = useProviders();
  const [authLoading, setAuthLoading] = useState<string | null>(null);
  const [authError, setAuthError] = useState<string | null>(null);

  const handleProviderLogin = async (providerName: string) => {
    try {
      setAuthLoading(providerName);
      setAuthError(null);

      // Get the current page URL as redirect URI
      const redirectUri = `${window.location.origin}/auth/callback/${providerName}`;

      // Get authorization URL from backend
      const authResponse = await authApi.getAuthorizationUrl(providerName, redirectUri);

      // Redirect to OAuth provider
      window.location.href = authResponse.authorization_url;
    } catch (err) {
      console.error('OAuth initiation failed:', err);

      let errorMessage = `Failed to start ${providerName} authentication`;
      if (err instanceof ApiError) {
        if (err.status === 400) {
          errorMessage = `${providerName} provider is not configured properly`;
        } else if (err.status === 500) {
          errorMessage = 'Server error - please try again';
        }
      }

      setAuthError(errorMessage);
    } finally {
      setAuthLoading(null);
    }
  };

  const handleTestConnection = async () => {
    try {
      await authApi.healthCheck();
      alert('✅ Connection successful! Backend is running and accessible.');
    } catch (err) {
      console.error('Health check failed:', err);
      alert('❌ Connection failed. Please check if the backend server is running.');
    }
  };

  if (loading) {
    return (
      <div className="container">
        <div className="card">
          <div style={{ textAlign: 'center' }}>
            <div className="loading-spinner"></div>
            <p>Loading OAuth providers...</p>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="container">
      <div className="card">
        <div style={{ textAlign: 'center', marginBottom: '2rem' }}>
          <Shield size={48} style={{ color: '#667eea', marginBottom: '1rem' }} />
          <h1>🔐 Bedrock SSO Proxy</h1>
          <p>Secure JWT authentication for AWS Bedrock access</p>
        </div>

        {error && (
          <div className="status-message error">
            <AlertCircle size={16} style={{ marginRight: '0.5rem' }} />
            {error}
            <button
              onClick={refreshProviders}
              className="btn btn-secondary"
              style={{ marginLeft: '1rem', padding: '0.5rem 1rem' }}
            >
              <RefreshCw size={16} />
              Retry
            </button>
          </div>
        )}

        {authError && (
          <div className="status-message error">
            <AlertCircle size={16} style={{ marginRight: '0.5rem' }} />
            {authError}
          </div>
        )}

        {providers.length === 0 && !error ? (
          <div className="card">
            <h3>No OAuth Providers Configured</h3>
            <p>No OAuth providers are currently configured on the server.</p>
            <p>
              To configure OAuth providers, add them to your <code>config.yaml</code>:
            </p>
            <pre
              style={{
                background: '#f7fafc',
                padding: '1rem',
                borderRadius: '8px',
                fontSize: '0.875rem',
                color: '#2d3748',
              }}
            >{`oauth:
  providers:
    google:
      client_id: "your-google-client-id"
      client_secret: "your-google-client-secret"
    github:
      client_id: "your-github-client-id"
      client_secret: "your-github-client-secret"`}</pre>
            <button onClick={refreshProviders} className="btn btn-primary">
              <RefreshCw size={16} />
              Refresh Providers
            </button>
          </div>
        ) : (
          <>
            <div className="card">
              <h2>Choose Authentication Provider</h2>
              <p>Select your preferred OAuth provider to get started:</p>

              <div className="oauth-providers">
                {providers.map((provider) => (
                  <button
                    key={provider.name}
                    onClick={() => handleProviderLogin(provider.name)}
                    className={`oauth-btn ${provider.name}`}
                    disabled={authLoading === provider.name}
                  >
                    <span className="icon">
                      {authLoading === provider.name ? '⏳' : getProviderIcon(provider.name)}
                    </span>
                    {authLoading === provider.name
                      ? `Connecting to ${provider.display_name}...`
                      : `Login with ${provider.display_name}`}
                  </button>
                ))}
              </div>

              <div
                style={{
                  marginTop: '1.5rem',
                  padding: '1rem',
                  background: '#f7fafc',
                  borderRadius: '8px',
                }}
              >
                <h4 style={{ marginBottom: '0.5rem', color: '#4a5568' }}>What happens next?</h4>
                <ol style={{ paddingLeft: '1.5rem', color: '#666' }}>
                  <li>You&apos;ll be redirected to your chosen provider</li>
                  <li>Sign in with your existing account</li>
                  <li>Authorize access to Bedrock SSO Proxy</li>
                  <li>Get your JWT token for Claude Code</li>
                </ol>
              </div>
            </div>

            <div className="card">
              <h3>Need Help?</h3>
              <p>Having trouble connecting? Check these common issues:</p>
              <ul style={{ paddingLeft: '1.5rem', color: '#666' }}>
                <li>Ensure the backend server is running</li>
                <li>Verify OAuth provider configuration</li>
                <li>Check redirect URI settings</li>
                <li>Review server logs for errors</li>
              </ul>
              <button onClick={handleTestConnection} className="btn btn-secondary">
                Test Connection
              </button>
            </div>
          </>
        )}
      </div>
    </div>
  );
}
