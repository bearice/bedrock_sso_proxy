import React, { useState } from 'react';
import { useProviders } from '../hooks/useProviders';
import { authApi, ApiError } from '../services/api';
import { Shield, RefreshCw, AlertCircle } from 'lucide-react';

const getProviderIcon = (name: string) => {
  switch (name) {
    case 'google': return '🔍';
    case 'github': return '🐙';  
    case 'microsoft': return '🪟';
    case 'gitlab': return '🦊';
    case 'auth0': return '🔐';
    case 'okta': return '🔑';
    default: return '🔒';
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
            <p>To configure OAuth providers, add them to your <code>config.yaml</code>:</p>
            <pre style={{ 
              background: '#f7fafc', 
              padding: '1rem', 
              borderRadius: '8px',
              fontSize: '0.875rem',
              color: '#2d3748'
            }}>{`oauth:
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
                      : `Login with ${provider.display_name}`
                    }
                  </button>
                ))}
              </div>
              
              <div style={{ marginTop: '1.5rem', padding: '1rem', background: '#f7fafc', borderRadius: '8px' }}>
                <h4 style={{ marginBottom: '0.5rem', color: '#4a5568' }}>What happens next?</h4>
                <ol style={{ paddingLeft: '1.5rem', color: '#666' }}>
                  <li>You'll be redirected to your chosen provider</li>
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