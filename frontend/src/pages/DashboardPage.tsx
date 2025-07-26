import { useState, useCallback, useEffect } from 'react';
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
  FileText,
} from 'lucide-react';

interface UserInfo {
  id?: number;
  provider_user_id: string;
  provider: string;
  email: string;
  display_name?: string;
  created_at: string;
  last_login?: string;
}

export function DashboardPage() {
  const { token, refreshToken, provider, user, expiresAt, scopes, refreshTokens, logout } =
    useAuth();

  const [copied, setCopied] = useState<string | null>(null);
  const [refreshing, setRefreshing] = useState(false);
  const [userInfo, setUserInfo] = useState<UserInfo | null>(null);

  // Fetch user info from /auth/me API
  useEffect(() => {
    const fetchUserInfo = async () => {
      if (!token) return;
      
      try {
        const response = await fetch('/auth/me', {
          headers: {
            'Authorization': `Bearer ${token}`,
          },
        });
        
        if (response.ok) {
          const data = await response.json();
          setUserInfo(data);
        }
      } catch (error) {
        console.error('Failed to fetch user info:', error);
      }
    };

    fetchUserInfo();
  }, [token]);

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
    const expirationDate = new Date(timestamp * 1000);

    if (diff <= 0) {
      return `Expired on ${expirationDate.toLocaleDateString()}`;
    }

    const days = Math.floor(diff / (24 * 3600));
    const hours = Math.floor((diff % (24 * 3600)) / 3600);

    let relativeTime = '';
    if (days > 30) {
      const months = Math.floor(days / 30);
      relativeTime = `${months} month${months > 1 ? 's' : ''} remaining`;
    } else if (days > 0) {
      relativeTime = `${days} day${days > 1 ? 's' : ''} remaining`;
    } else if (hours > 0) {
      const minutes = Math.floor((diff % 3600) / 60);
      relativeTime = `${hours}h ${minutes}m remaining`;
    } else {
      const minutes = Math.floor(diff / 60);
      relativeTime = `${minutes} minute${minutes > 1 ? 's' : ''} remaining`;
    }

    return `${relativeTime} (expires ${expirationDate.toLocaleDateString()} at ${expirationDate.toLocaleTimeString()})`;
  };

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

  const currentDomain = window.location.origin;

  return (
    <div className="container">
      {/* User Info Header */}
      <div className="card">
        <div className="user-info">
          <div className="user-details">
            <h3>
              <User size={20} style={{ marginRight: '0.5rem', verticalAlign: 'text-bottom' }} />
              Welcome back, {userInfo?.display_name || userInfo?.email || user}!
            </h3>
            <p>
              <strong>Email:</strong> {userInfo?.email || user}
            </p>
            <p>
              <strong>Provider:</strong> {getProviderDisplayName(provider || '')}
            </p>
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
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              padding: '0.75rem',
              background: '#f7fafc',
              borderRadius: '8px',
              marginTop: '1rem',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <Clock size={16} style={{ color: '#4a5568' }} />
              <span style={{ color: '#4a5568' }}>Token {formatExpirationTime(expiresAt)}</span>
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

      {/* Claude Code Quick Start */}
      <div className="card" style={{ background: '#f8fafc', border: '2px solid #4f46e5', borderRadius: '12px' }}>
        <h2 style={{ color: '#4f46e5', fontSize: '1.5rem', marginBottom: '1rem' }}>
          <Terminal size={24} style={{ marginRight: '0.5rem', verticalAlign: 'text-bottom' }} />
          🚀 Use with Claude Code
        </h2>
        <p style={{ fontSize: '1.1rem', marginBottom: '1.5rem', color: '#374151', fontWeight: '500' }}>
          Ready to use! Copy this command to use Claude Code with your authenticated proxy:
        </p>

        <div style={{
          background: '#1f2937',
          color: '#f9fafb',
          padding: '1rem',
          borderRadius: '8px',
          marginBottom: '1rem',
          fontFamily: 'monospace',
          fontSize: '0.9rem',
          wordBreak: 'break-all',
          border: '1px solid #374151'
        }}>
          export ANTHROPIC_AUTH_TOKEN={token?.substring(0, 40)}...<br />
          export ANTHROPIC_BASE_URL={currentDomain}/anthropic<br />
          claude
        </div>

        <div style={{ display: 'flex', gap: '1rem', flexWrap: 'wrap' }}>
          <button
            onClick={() => copyToClipboard(
              `export ANTHROPIC_AUTH_TOKEN=${token}\nexport ANTHROPIC_BASE_URL=${currentDomain}/anthropic\nclaude`,
              'claude-command'
            )}
            className="btn"
            style={{
              background: '#4f46e5',
              color: 'white',
              border: '1px solid #4f46e5'
            }}
          >
            <Copy size={16} />
            {copied === 'claude-command' ? 'Copied!' : 'Copy Full Command'}
          </button>

          <button
            onClick={() => copyToClipboard(token!, 'token-quick')}
            className="btn"
            style={{
              background: '#6b7280',
              color: 'white',
              border: '1px solid #6b7280'
            }}
          >
            <Key size={16} />
            {copied === 'token-quick' ? 'Copied!' : 'Copy Token Only'}
          </button>
        </div>

        <div style={{
          background: '#ecfdf5',
          color: '#047857',
          padding: '0.75rem',
          borderRadius: '6px',
          marginTop: '1rem',
          fontSize: '0.9rem',
          border: '1px solid #a7f3d0'
        }}>
          💡 <strong>Quick tip:</strong> Run this command in your terminal to start using Claude Code with this proxy immediately!
        </div>
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
            <button onClick={() => copyToClipboard(token!, 'token')} className="copy-btn">
              <Copy size={14} />
              {copied === 'token' ? 'Copied!' : 'Copy Token'}
            </button>
          </div>

          {refreshToken && refreshToken.trim() && (
            <div className="token-box">
              <h4>Refresh Token</h4>
              <div className="token-value">{refreshToken}</div>
              <button onClick={() => copyToClipboard(refreshToken, 'refresh')} className="copy-btn">
                <Copy size={14} />
                {copied === 'refresh' ? 'Copied!' : 'Copy Refresh Token'}
              </button>
            </div>
          )}

          {scopes && scopes.length > 0 && (
            <div style={{ marginTop: '1rem' }}>
              <h4>Granted Scopes:</h4>
              <div
                style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem', marginTop: '0.5rem' }}
              >
                {scopes.map((scope, index) => (
                  <span
                    key={index}
                    style={{
                      background: '#e2e8f0',
                      color: '#4a5568',
                      padding: '0.25rem 0.75rem',
                      borderRadius: '12px',
                      fontSize: '0.875rem',
                      fontWeight: '500',
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
        <p>Use your JWT token to authenticate API requests to this Bedrock proxy:</p>

        <div
          style={{
            background: '#fff3cd',
            padding: '1rem',
            borderRadius: '8px',
            marginBottom: '1rem',
            border: '1px solid #ffeaa7',
          }}
        >
          <strong>⚠️ Important:</strong> This is a custom proxy server, not the official Claude Code
          integration. For standard AWS Bedrock usage with Claude Code, see the{' '}
          <a
            href="https://docs.anthropic.com/en/docs/claude-code/amazon-bedrock"
            target="_blank"
            rel="noopener noreferrer"
          >
            official documentation
          </a>
          .
        </div>

        <h4>API Usage</h4>
        <p>
          This proxy supports both Bedrock and Anthropic API formats for maximum compatibility. Use
          the token as a Bearer token in the Authorization header:
        </p>
        <pre>{`Authorization: Bearer ${token?.substring(0, 30)}...`}</pre>

        <div
          style={{
            background: '#e8f5e8',
            padding: '1rem',
            borderRadius: '8px',
            marginTop: '1rem',
            border: '1px solid #b8d4b8',
          }}
        >
          <strong>✨ New:</strong> Anthropic API format support! Use <code>/v1/messages</code> with
          standard Anthropic request format for better compatibility with Anthropic SDKs and LLM
          gateways.
        </div>

        <h4>Available Endpoints</h4>
        <div style={{ marginBottom: '1rem' }}>
          <strong>Health & Status:</strong>
          <ul>
            <li>
              <code>GET /health</code> - Health check (no auth required)
            </li>
          </ul>
        </div>

        <div style={{ marginBottom: '1rem' }}>
          <strong>Bedrock Format (AWS Native):</strong>
          <ul>
            <li>
              <code>
                POST /bedrock/model/{'{'}
                {'{'}model_id{'}'}/invoke
              </code>{' '}
              - Standard invocation
            </li>
            <li>
              <code>
                POST /bedrock/model/{'{'}
                {'{'}model_id{'}'}/invoke-with-response-stream
              </code>{' '}
              - Streaming responses
            </li>
          </ul>
          <p style={{ fontSize: '0.9rem', color: '#666', margin: '0.5rem 0 0 1rem' }}>
            Uses AWS model IDs like <code>anthropic.claude-sonnet-4-20250514-v1:0</code> in the URL
            path
          </p>
        </div>

        <div style={{ marginBottom: '1rem' }}>
          <strong>Anthropic Format (Standard API):</strong>
          <ul>
            <li>
              <code>POST /anthropic/v1/messages</code> - Standard Anthropic API (supports streaming)
            </li>
          </ul>
          <p style={{ fontSize: '0.9rem', color: '#666', margin: '0.5rem 0 0 1rem' }}>
            Uses standard model names like <code>claude-sonnet-4-20250514</code> in the request body
          </p>
        </div>

        <h4>Claude Code Integration (LLM Gateway)</h4>
        <p>Configure Claude Code to use this proxy as an LLM gateway:</p>

        <h5>Method 1: Environment Variables</h5>
        <pre>{`export ANTHROPIC_BEDROCK_BASE_URL="${currentDomain}"
export ANTHROPIC_AUTH_TOKEN="${token?.substring(0, 20)}..."
export CLAUDE_CODE_SKIP_BEDROCK_AUTH=1
export CLAUDE_CODE_USE_BEDROCK=1`}</pre>

        <h5>Method 2: Settings File</h5>
        <p>
          Add to your <code>~/.claude/settings.json</code>:
        </p>
        <pre>{`{
  "env": {
    "ANTHROPIC_BEDROCK_BASE_URL": "${currentDomain}",
    "ANTHROPIC_AUTH_TOKEN": "${token?.substring(0, 20)}...",
    "CLAUDE_CODE_SKIP_BEDROCK_AUTH": "1",
    "CLAUDE_CODE_USE_BEDROCK": "1"
  }
}`}</pre>

        <div
          style={{
            background: '#d1ecf1',
            padding: '1rem',
            borderRadius: '8px',
            marginTop: '1rem',
            border: '1px solid #bee5eb',
          }}
        >
          <strong>💡 Tip:</strong> For official AWS Bedrock support, use{' '}
          <code>export CLAUDE_CODE_USE_BEDROCK=1</code>
          and configure AWS credentials instead. This requires proper AWS IAM permissions and
          enabled Claude models.
        </div>
      </div>

      {/* Testing Section */}
      <div className="card">
        <h3>
          <Shield size={20} style={{ marginRight: '0.5rem', verticalAlign: 'text-bottom' }} />
          🧪 Test Your Setup
        </h3>
        <p>
          Verify your authentication is working with test requests. Choose your preferred API
          format:
        </p>

        <div style={{ display: 'grid', gap: '1.5rem', marginTop: '1rem' }}>
          {/* Bedrock Format Example */}
          <div>
            <h4>Bedrock Format (AWS Native):</h4>
            <pre>{`curl -X POST "${currentDomain}/bedrock/model/anthropic.claude-sonnet-4-20250514-v1:0/invoke" \\
  -H "Authorization: Bearer ${token?.substring(0, 30)}..." \\
  -H "Content-Type: application/json" \\
  -d '{
    "anthropic_version": "bedrock-2023-05-31",
    "max_tokens": 1000,
    "messages": [{"role": "user", "content": "Hello!"}]
  }'`}</pre>
          </div>

          {/* Anthropic Format Example */}
          <div>
            <h4>Anthropic Format (Standard API):</h4>
            <pre>{`curl -X POST "${currentDomain}/anthropic/v1/messages" \\
  -H "Authorization: Bearer ${token?.substring(0, 30)}..." \\
  -H "Content-Type: application/json" \\
  -d '{
    "model": "claude-sonnet-4-20250514",
    "max_tokens": 1000,
    "messages": [{"role": "user", "content": "Hello!"}]
  }'`}</pre>
          </div>

          {/* Anthropic Streaming Example */}
          <div>
            <h4>Anthropic Format (Streaming):</h4>
            <pre>{`curl -X POST "${currentDomain}/anthropic/v1/messages" \\
  -H "Authorization: Bearer ${token?.substring(0, 30)}..." \\
  -H "Content-Type: application/json" \\
  -d '{
    "model": "claude-sonnet-4-20250514",
    "max_tokens": 1000,
    "messages": [{"role": "user", "content": "Hello!"}],
    "stream": true
  }'`}</pre>
          </div>
        </div>

        <h4 style={{ marginTop: '1.5rem' }}>Using Claude Code:</h4>
        <p>
          With ANTHROPIC_BEDROCK_BASE_URL configured, Claude Code will automatically use the
          Anthropic format:
        </p>
        <pre>claude-code &quot;Hello, can you help me test this setup?&quot;</pre>

        <div style={{ marginTop: '1rem', display: 'flex', gap: '1rem', flexWrap: 'wrap' }}>
          <button
            onClick={() =>
              copyToClipboard(
                `curl -X POST "${currentDomain}/bedrock/model/anthropic.claude-sonnet-4-20250514-v1:0/invoke" -H "Authorization: Bearer ${token}" -H "Content-Type: application/json" -d '{"anthropic_version": "bedrock-2023-05-31", "max_tokens": 1000, "messages": [{"role": "user", "content": "Hello!"}]}'`,
                'curl-bedrock'
              )
            }
            className="btn btn-secondary"
          >
            <Copy size={16} />
            {copied === 'curl-bedrock' ? 'Copied!' : 'Copy Bedrock Command'}
          </button>

          <button
            onClick={() =>
              copyToClipboard(
                `curl -X POST "${currentDomain}/anthropic/v1/messages" -H "Authorization: Bearer ${token}" -H "Content-Type: application/json" -d '{"model": "claude-sonnet-4-20250514", "max_tokens": 1000, "messages": [{"role": "user", "content": "Hello!"}]}'`,
                'curl-anthropic'
              )
            }
            className="btn btn-secondary"
          >
            <Copy size={16} />
            {copied === 'curl-anthropic' ? 'Copied!' : 'Copy Anthropic Command'}
          </button>

          <a href="/health" target="_blank" rel="noopener noreferrer" className="btn btn-primary">
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
            <a href="#" className="btn btn-secondary">
              View Docs
            </a>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
            <div style={{ flex: 1 }}>
              <strong>Claude Code Guide</strong>
              <p style={{ margin: '0.25rem 0', color: '#666' }}>
                Learn how to use Claude Code effectively
              </p>
            </div>
            <a
              href="https://docs.anthropic.com/en/docs/claude-code"
              target="_blank"
              rel="noopener noreferrer"
              className="btn btn-secondary"
            >
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
            <a
              href="/health"
              target="_blank"
              rel="noopener noreferrer"
              className="btn btn-secondary"
            >
              <ExternalLink size={16} />
              Health Check
            </a>
          </div>
        </div>
      </div>
    </div>
  );
}
