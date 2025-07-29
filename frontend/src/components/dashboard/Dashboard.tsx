import { useState, useCallback, useEffect } from 'react';
import { useAuth } from '../../hooks/useAuth';
import { apiKeyApi } from '../../services/api';
import { ApiKeyInfo } from '../../types/auth';
import {
  Copy,
  User,
  Shield,
  Key,
  ExternalLink,
  Terminal,
  FileText,
  Plus,
  AlertTriangle,
} from 'lucide-react';

export function Dashboard() {
  const { token } = useAuth();
  const [copied, setCopied] = useState<string | null>(null);
  const [apiKeys, setApiKeys] = useState<ApiKeyInfo[]>([]);
  const [isLoadingApiKeys, setIsLoadingApiKeys] = useState(true);

  // Load API keys to check if user has any
  const loadApiKeys = useCallback(async () => {
    if (!token) return;

    try {
      setIsLoadingApiKeys(true);
      const keys = await apiKeyApi.listApiKeys(token);
      setApiKeys(keys);
    } catch (err) {
      console.error('Failed to load API keys:', err);
    } finally {
      setIsLoadingApiKeys(false);
    }
  }, [token]);

  // Load API keys on initial render
  useEffect(() => {
    loadApiKeys();
  }, [loadApiKeys]);

  // Get active API keys count
  const activeApiKeysCount = apiKeys.filter(
    (key) => !key.revoked_at && (!key.expires_at || new Date(key.expires_at) > new Date())
  ).length;

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

  const currentDomain = window.location.origin;

  // Function to switch to API keys tab
  const switchToApiKeys = () => {
    window.dispatchEvent(new CustomEvent('switchTab', { detail: 'api-keys' }));
  };

  return (
    <div>
      {/* Header */}
      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          marginBottom: '2rem',
        }}
      >
        <div>
          <h2 style={{ margin: 0, display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <User size={24} />
            Dashboard
          </h2>
          <p style={{ margin: '0.5rem 0 0 0', color: '#374151', fontWeight: '500' }}>
            Welcome back! Here's your quick start guide for using the proxy
          </p>
        </div>
      </div>

      {/* API Key Recommendation */}
      {(!isLoadingApiKeys && activeApiKeysCount === 0) &&
        (
          <div
            className="card"
            style={{ background: '#fef3c7', border: '2px solid #f59e0b', borderRadius: '12px' }}
          >
            <h2 style={{ color: '#92400e', fontSize: '1.5rem', marginBottom: '1rem' }}>
              <AlertTriangle size={24} style={{ marginRight: '0.5rem', verticalAlign: 'text-bottom' }} />
              ⚠️ Create an API Key First
            </h2>
            <div style={{ display: 'flex', gap: '1rem', flexWrap: 'wrap', marginBottom: '1rem' }}>
              <button
                onClick={switchToApiKeys}
                className="btn"
                style={{
                  background: '#f59e0b',
                  color: 'white',
                  border: '1px solid #f59e0b',
                }}
              >
                <Plus size={16} />
                Create Your First API Key
              </button>
            </div>
          </div>
        ) || (
          <div
            className="card"
            style={{ background: '#f8fafc', border: '2px solid #4f46e5', borderRadius: '12px' }}
          >
            <h2 style={{ color: '#4f46e5', fontSize: '1.5rem', marginBottom: '1rem' }}>
              <Terminal size={24} style={{ marginRight: '0.5rem', verticalAlign: 'text-bottom' }} />
              🚀 Use with Claude Code
            </h2>
            <p
              style={{
                fontSize: '1.1rem',
                marginBottom: '1.5rem',
                color: '#374151',
                fontWeight: '500',
              }}
            >
              Great! You have {activeApiKeysCount} active API key{activeApiKeysCount !== 1 ? 's' : ''}. Use an API key with Claude Code for the best experience:
            </p>

            <div
              style={{
                background: '#1f2937',
                color: '#f9fafb',
                padding: '1rem',
                borderRadius: '8px',
                marginBottom: '1rem',
                fontFamily: 'monospace',
                fontSize: '0.9rem',
                wordBreak: 'break-all',
                border: '1px solid #374151',
              }}
            >
              export ANTHROPIC_AUTH_TOKEN=SSOK_your_api_key_here
              <br />
              export ANTHROPIC_BASE_URL={currentDomain}/anthropic
              <br />
              claude
            </div>

            <div style={{ display: 'flex', gap: '1rem', flexWrap: 'wrap' }}>
              <button
                onClick={switchToApiKeys}
                className="btn"
                style={{
                  background: '#4f46e5',
                  color: 'white',
                  border: '1px solid #4f46e5',
                }}
              >
                <Key size={16} />
                View Your API Keys
              </button>
            </div>
          </div>
        )}
      {/* Claude Code Setup Instructions */}
      <div className="setup-section">
        <h3>
          <Terminal size={20} style={{ marginRight: '0.5rem', verticalAlign: 'text-bottom' }} />
          🔧 Claude Code Setup
        </h3>

        <h4>Claude Code Integration</h4>
        <p>Configure Claude Code to use this proxy as an LLM gateway:</p>

        <h5>Method 1: Anthropic Gateway Mode</h5>
        <pre>{`export ANTHROPIC_AUTH_TOKEN="SSOK_your_api_key_here"
export ANTHROPIC_BASE_URL="${currentDomain}/anthropic"`}</pre>

        <h5>Method 2: Bedrock Gateway Mode</h5>
        <pre>{`export ANTHROPIC_BEDROCK_BASE_URL="${currentDomain}"
export ANTHROPIC_AUTH_TOKEN="${activeApiKeysCount > 0 ? 'SSOK_your_api_key_here' : token?.substring(0, 20) + '...'}"
export CLAUDE_CODE_SKIP_BEDROCK_AUTH=1
export CLAUDE_CODE_USE_BEDROCK=1`}</pre>

        <h4>API Usage</h4>
        <p>
          This proxy supports both Bedrock and Anthropic API formats for maximum compatibility.
          Use the API key as a Bearer token in the Authorization header:
        </p>
        <pre>{`Authorization: Bearer SSOK_your_api_key_here`}</pre>

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
            Uses AWS model IDs like <code>anthropic.claude-sonnet-4-20250514-v1:0</code> in the
            URL path
          </p>
        </div>

        <div style={{ marginBottom: '1rem' }}>
          <strong>Anthropic Format (Standard API):</strong>
          <ul>
            <li>
              <code>POST /anthropic/v1/messages</code> - Standard Anthropic API (supports
              streaming)
            </li>
          </ul>
          <p style={{ fontSize: '0.9rem', color: '#666', margin: '0.5rem 0 0 1rem' }}>
            Uses standard model names like <code>claude-sonnet-4-20250514</code> in the request
            body
          </p>
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
  -H "Authorization: Bearer SSOK_your_api_key_here" \\
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
  -H "Authorization: Bearer SSOK_your_api_key_here" \\
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
  -H "Authorization: Bearer SSOK_your_api_key_here" \\
  -H "Content-Type: application/json" \\
  -d '{
    "model": "claude-sonnet-4-20250514",
    "max_tokens": 1000,
    "messages": [{"role": "user", "content": "Hello!"}],
    "stream": true
  }'`}</pre>
          </div>
        </div>

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
        </div>
      </div>
    </div>
  );
}