import { useState, useCallback } from 'react';
import { useAuth } from '../hooks/useAuth';
import { 
  LogOut, 
  Copy, 
  RefreshCw, 
  User, 
  Shield, 
  Clock, 
  Key,
  ExternalLink,
  Terminal,
  FileText
} from 'lucide-react';

export function DashboardPage() {
  const { 
    token, 
    refreshToken, 
    provider, 
    user, 
    expiresAt, 
    scopes,
    refreshTokens,
    logout 
  } = useAuth();

  const [copied, setCopied] = useState<string | null>(null);
  const [refreshing, setRefreshing] = useState(false);

  const copyToClipboard = useCallback(async (text: string, type: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(type);
      setTimeout(() => setCopied(null), 2000);
    } catch (err) {
      console.error('Failed to copy:', err);
      // Fallback for older browsers
      const textArea = document.createElement('textarea');
      textArea.value = text;
      document.body.appendChild(textArea);
      textArea.select();
      document.execCommand('copy');
      document.body.removeChild(textArea);
      setCopied(type);
      setTimeout(() => setCopied(null), 2000);
    }
  }, []);

  const handleRefreshToken = useCallback(async () => {
    if (!refreshToken) return;
    
    try {
      setRefreshing(true);
      await refreshTokens(refreshToken);
    } catch (error) {
      console.error('Failed to refresh token:', error);
      alert('Failed to refresh token. Please log in again.');
    } finally {
      setRefreshing(false);
    }
  }, [refreshToken, refreshTokens]);

  const formatExpirationTime = (timestamp: number) => {
    const now = Date.now() / 1000;
    const diff = timestamp - now;
    
    if (diff <= 0) {
      return 'Expired';
    }
    
    const days = Math.floor(diff / (24 * 3600));
    const hours = Math.floor((diff % (24 * 3600)) / 3600);
    
    if (days > 30) {
      const months = Math.floor(days / 30);
      return `${months} month${months > 1 ? 's' : ''} remaining`;
    } else if (days > 0) {
      return `${days} day${days > 1 ? 's' : ''} remaining`;
    } else if (hours > 0) {
      const minutes = Math.floor((diff % 3600) / 60);
      return `${hours}h ${minutes}m remaining`;
    } else {
      const minutes = Math.floor(diff / 60);
      return `${minutes} minute${minutes > 1 ? 's' : ''} remaining`;
    }
  };

  const getProviderDisplayName = (provider: string) => {
    const names: { [key: string]: string } = {
      google: 'Google',
      github: 'GitHub', 
      microsoft: 'Microsoft',
      gitlab: 'GitLab',
      auth0: 'Auth0',
      okta: 'Okta'
    };
    return names[provider] || provider;
  };

  const currentDomain = window.location.origin;

  return (
    <div className="container">
      {/* User Info Header */}
      <div className="card">
        <div className="user-info">
          <div className="user-details">
            <h3>
              <User size={20} style={{ marginRight: '0.5rem', verticalAlign: 'text-bottom' }} />
              Welcome back!
            </h3>
            <p><strong>User ID:</strong> {user}</p>
            <p><strong>Provider:</strong> {getProviderDisplayName(provider || '')}</p>
          </div>
          <div>
            <span className="provider-badge">{getProviderDisplayName(provider || '')}</span>
            <button onClick={logout} className="btn btn-danger" style={{ marginLeft: '1rem' }}>
              <LogOut size={16} />
              Logout
            </button>
          </div>
        </div>

        {expiresAt && (
          <div style={{ 
            display: 'flex', 
            alignItems: 'center', 
            justifyContent: 'space-between',
            padding: '0.75rem',
            background: '#f7fafc',
            borderRadius: '8px',
            marginTop: '1rem'
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <Clock size={16} style={{ color: '#4a5568' }} />
              <span style={{ color: '#4a5568' }}>
                Token {formatExpirationTime(expiresAt)}
              </span>
            </div>
            {refreshToken && (
              <button 
                onClick={handleRefreshToken}
                disabled={refreshing}
                className="btn btn-secondary"
                style={{ padding: '0.5rem 1rem' }}
              >
                <RefreshCw size={16} className={refreshing ? 'loading-spinner' : ''} />
                {refreshing ? 'Refreshing...' : 'Refresh Token'}
              </button>
            )}
          </div>
        )}
      </div>

      {/* Token Display */}
      <div className="card">
        <h2>
          <Key size={24} style={{ marginRight: '0.5rem', verticalAlign: 'text-bottom' }} />
          JWT Access Token
        </h2>
        <p>Use this token to authenticate your requests to the Bedrock API.</p>
        
        <div className="token-display">
          <div className="token-box">
            <h4>Access Token</h4>
            <div className="token-value">{token}</div>
            <button 
              onClick={() => copyToClipboard(token!, 'token')}
              className="copy-btn"
            >
              <Copy size={14} />
              {copied === 'token' ? 'Copied!' : 'Copy Token'}
            </button>
          </div>

          {refreshToken && refreshToken.trim() && (
            <div className="token-box">
              <h4>Refresh Token</h4>
              <div className="token-value">{refreshToken}</div>
              <button 
                onClick={() => copyToClipboard(refreshToken, 'refresh')}
                className="copy-btn"
              >
                <Copy size={14} />
                {copied === 'refresh' ? 'Copied!' : 'Copy Refresh Token'}
              </button>
            </div>
          )}

          {scopes && scopes.length > 0 && (
            <div style={{ marginTop: '1rem' }}>
              <h4>Granted Scopes:</h4>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem', marginTop: '0.5rem' }}>
                {scopes.map((scope, index) => (
                  <span 
                    key={index}
                    style={{
                      background: '#e2e8f0',
                      color: '#4a5568',
                      padding: '0.25rem 0.75rem',
                      borderRadius: '12px',
                      fontSize: '0.875rem',
                      fontWeight: '500'
                    }}
                  >
                    {scope}
                  </span>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Claude Code Setup Instructions */}
      <div className="setup-section">
        <h3>
          <Terminal size={20} style={{ marginRight: '0.5rem', verticalAlign: 'text-bottom' }} />
          🔧 Claude Code Setup
        </h3>
        <p>Configure Claude Code to use your Bedrock proxy with these simple steps:</p>

        <h4>Method 1: Environment Variables (Recommended)</h4>
        <pre>export BEDROCK_TOKEN=&quot;{token}&quot;
export BEDROCK_ENDPOINT=&quot;{currentDomain}&quot;</pre>

        <h4>Method 2: Claude Code Configuration</h4>
        <pre>claude-code config set bedrock.token &quot;{token}&quot;
claude-code config set bedrock.endpoint &quot;{currentDomain}&quot;</pre>

        <h4>Method 3: Configuration File</h4>
        <p>Add to your <code>~/.claude/config.json</code>:</p>
        <pre>{`{
  "bedrock": {
    "endpoint": "${currentDomain}",
    "token": "${token?.substring(0, 20)}..."
  }
}`}</pre>

        <h4>Method 4: CLAUDE.md Configuration</h4>
        <p>Add to your project&apos;s <code>CLAUDE.md</code> file:</p>
        <pre>{`# Bedrock Configuration
export BEDROCK_TOKEN="${token?.substring(0, 20)}..."
export BEDROCK_ENDPOINT="${currentDomain}"`}</pre>
      </div>

      {/* Testing Section */}
      <div className="card">
        <h3>
          <Shield size={20} style={{ marginRight: '0.5rem', verticalAlign: 'text-bottom' }} />
          🧪 Test Your Setup
        </h3>
        <p>Verify your authentication is working with a test request:</p>

        <h4>Using curl:</h4>
        <pre>{`curl -X POST "${currentDomain}/model/anthropic.claude-3-sonnet-20240229-v1:0/invoke" \\
  -H "Authorization: Bearer ${token?.substring(0, 30)}..." \\
  -H "Content-Type: application/json" \\
  -d '{
    "anthropic_version": "bedrock-2023-05-31",
    "max_tokens": 1000,
    "messages": [{"role": "user", "content": "Hello!"}]
  }'`}</pre>

        <h4>Using Claude Code:</h4>
        <pre>claude-code &quot;Hello, can you help me test this setup?&quot;</pre>

        <div style={{ marginTop: '1rem', display: 'flex', gap: '1rem', flexWrap: 'wrap' }}>
          <button 
            onClick={() => copyToClipboard(
              `curl -X POST "${currentDomain}/model/anthropic.claude-3-sonnet-20240229-v1:0/invoke" -H "Authorization: Bearer ${token}" -H "Content-Type: application/json" -d '{"anthropic_version": "bedrock-2023-05-31", "max_tokens": 1000, "messages": [{"role": "user", "content": "Hello!"}]}'`,
              'curl'
            )}
            className="btn btn-secondary"
          >
            <Copy size={16} />
            {copied === 'curl' ? 'Copied!' : 'Copy curl Command'}
          </button>
          
          <a 
            href="/health" 
            target="_blank"
            rel="noopener noreferrer"
            className="btn btn-primary"
          >
            <ExternalLink size={16} />
            Test Health Endpoint
          </a>
        </div>
      </div>

      {/* Documentation Section */}
      <div className="card">
        <h3>
          <FileText size={20} style={{ marginRight: '0.5rem', verticalAlign: 'text-bottom' }} />
          📚 Documentation & Support
        </h3>
        <p>Need more help? Check out these resources:</p>
        
        <div style={{ display: 'grid', gap: '1rem', marginTop: '1rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
            <div style={{ flex: 1 }}>
              <strong>API Documentation</strong>
              <p style={{ margin: '0.25rem 0', color: '#666' }}>
                Complete API reference for all endpoints
              </p>
            </div>
            <a href="#" className="btn btn-secondary">View Docs</a>
          </div>
          
          <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
            <div style={{ flex: 1 }}>
              <strong>Claude Code Guide</strong>
              <p style={{ margin: '0.25rem 0', color: '#666' }}>
                Learn how to use Claude Code effectively
              </p>
            </div>
            <a href="https://docs.anthropic.com/en/docs/claude-code" target="_blank" rel="noopener noreferrer" className="btn btn-secondary">
              <ExternalLink size={16} />
              Visit Guide
            </a>
          </div>
          
          <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
            <div style={{ flex: 1 }}>
              <strong>Server Health</strong>
              <p style={{ margin: '0.25rem 0', color: '#666' }}>
                Check server status and configuration
              </p>
            </div>
            <a href="/health" target="_blank" rel="noopener noreferrer" className="btn btn-secondary">
              <ExternalLink size={16} />
              Health Check
            </a>
          </div>
        </div>
      </div>
    </div>
  );
}