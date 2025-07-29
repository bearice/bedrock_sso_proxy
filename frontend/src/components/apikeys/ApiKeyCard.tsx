import { useState, useCallback } from 'react';
import { ApiKeyInfo } from '../../types/auth';
import { Copy, Trash2, AlertTriangle, Key, Calendar, CheckCircle, XCircle } from 'lucide-react';

interface ApiKeyCardProps {
  apiKey: ApiKeyInfo;
  onRevoke: (keyId: number) => Promise<void>;
  newlyCreatedKey?: string; // Only provided for newly created keys
}

export function ApiKeyCard({ apiKey, onRevoke, newlyCreatedKey }: ApiKeyCardProps) {
  const [copied, setCopied] = useState(false);
  const [isRevoking, setIsRevoking] = useState(false);
  const [showRevokeConfirm, setShowRevokeConfirm] = useState(false);

  const copyToClipboard = useCallback(async (text: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch (err) {
      console.error('Failed to copy:', err);
      // Fallback for older browsers
      const textArea = document.createElement('textarea');
      textArea.value = text;
      document.body.appendChild(textArea);
      textArea.select();
      document.execCommand('copy');
      document.body.removeChild(textArea);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  }, []);

  const handleRevoke = useCallback(async () => {
    try {
      setIsRevoking(true);
      await onRevoke(apiKey.id);
    } catch (error) {
      console.error('Failed to revoke API key:', error);
    } finally {
      setIsRevoking(false);
      setShowRevokeConfirm(false);
    }
  }, [apiKey.id, onRevoke]);

  const isExpired = apiKey.expires_at && new Date(apiKey.expires_at) < new Date();
  const isRevoked = !!apiKey.revoked_at;
  const isActive = !isExpired && !isRevoked;

  const getStatusColor = () => {
    if (isRevoked) return '#dc3545'; // red
    if (isExpired) return '#fd7e14'; // orange
    return '#28a745'; // green
  };

  const getStatusIcon = () => {
    if (isRevoked) return <XCircle size={16} style={{ color: '#dc3545' }} />;
    if (isExpired) return <AlertTriangle size={16} style={{ color: '#fd7e14' }} />;
    return <CheckCircle size={16} style={{ color: '#28a745' }} />;
  };

  const getStatusText = () => {
    if (isRevoked) return 'Revoked';
    if (isExpired) return 'Expired';
    return 'Active';
  };

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    });
  };

  const getExpirationWarning = () => {
    if (!apiKey.expires_at || isRevoked) return null;
    
    const expiryDate = new Date(apiKey.expires_at);
    const now = new Date();
    const daysUntilExpiry = Math.ceil((expiryDate.getTime() - now.getTime()) / (1000 * 60 * 60 * 24));
    
    if (daysUntilExpiry <= 0) return null; // Already handled by isExpired
    if (daysUntilExpiry <= 7) {
      return (
        <div style={{
          display: 'flex',
          alignItems: 'center',
          gap: '0.25rem',
          color: '#fd7e14',
          fontSize: '0.875rem',
          marginTop: '0.5rem'
        }}>
          <AlertTriangle size={14} />
          Expires in {daysUntilExpiry} day{daysUntilExpiry !== 1 ? 's' : ''}
        </div>
      );
    }
    return null;
  };

  return (
    <div style={{
      border: `2px solid ${getStatusColor()}`,
      borderRadius: '8px',
      padding: '1rem',
      background: isActive ? '#ffffff' : '#f8f9fa',
      opacity: isActive ? 1 : 0.8,
    }}>
      {/* Header */}
      <div style={{
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'flex-start',
        marginBottom: '0.75rem'
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <Key size={20} style={{ color: '#6c757d' }} />
          <h4 style={{ margin: 0, fontSize: '1.1rem' }}>{apiKey.name}</h4>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          {getStatusIcon()}
          <span style={{
            fontSize: '0.875rem',
            fontWeight: '500',
            color: getStatusColor()
          }}>
            {getStatusText()}
          </span>
        </div>
      </div>

      {/* Key Display (only for newly created keys) */}
      {newlyCreatedKey && (
        <div style={{
          background: '#1f2937',
          color: '#f9fafb',
          padding: '0.75rem',
          borderRadius: '6px',
          marginBottom: '0.75rem',
          fontFamily: 'monospace',
          fontSize: '0.875rem',
          wordBreak: 'break-all',
          border: '1px solid #374151'
        }}>
          {newlyCreatedKey}
        </div>
      )}

      {/* Metadata */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem', fontSize: '0.875rem', color: '#6c757d' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <Calendar size={14} />
          <span>Created: {formatDate(apiKey.created_at)}</span>
        </div>
        
        {apiKey.expires_at && (
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <AlertTriangle size={14} />
            <span>Expires: {formatDate(apiKey.expires_at)}</span>
          </div>
        )}

        {apiKey.revoked_at && (
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <XCircle size={14} />
            <span>Revoked: {formatDate(apiKey.revoked_at)}</span>
          </div>
        )}
      </div>

      {/* Expiration Warning */}
      {getExpirationWarning()}

      {/* Actions */}
      <div style={{
        display: 'flex',
        gap: '0.5rem',
        marginTop: '1rem',
        paddingTop: '0.75rem',
        borderTop: '1px solid #e9ecef'
      }}>
        {newlyCreatedKey && (
          <button
            onClick={() => copyToClipboard(newlyCreatedKey)}
            className="btn"
            style={{
              background: '#4f46e5',
              color: 'white',
              border: '1px solid #4f46e5',
              padding: '0.5rem 1rem',
              fontSize: '0.875rem'
            }}
          >
            <Copy size={14} />
            {copied ? 'Copied!' : 'Copy Key'}
          </button>
        )}

        {isActive && !showRevokeConfirm && (
          <button
            onClick={() => setShowRevokeConfirm(true)}
            className="btn"
            style={{
              background: '#dc3545',
              color: 'white',
              border: '1px solid #dc3545',
              padding: '0.5rem 1rem',
              fontSize: '0.875rem'
            }}
          >
            <Trash2 size={14} />
            Revoke
          </button>
        )}

        {showRevokeConfirm && (
          <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
            <span style={{ fontSize: '0.875rem', color: '#dc3545' }}>
              Are you sure?
            </span>
            <button
              onClick={handleRevoke}
              disabled={isRevoking}
              className="btn"
              style={{
                background: '#dc3545',
                color: 'white',
                border: '1px solid #dc3545',
                padding: '0.375rem 0.75rem',
                fontSize: '0.75rem'
              }}
            >
              {isRevoking ? 'Revoking...' : 'Yes, Revoke'}
            </button>
            <button
              onClick={() => setShowRevokeConfirm(false)}
              className="btn"
              style={{
                background: '#6c757d',
                color: 'white',
                border: '1px solid #6c757d',
                padding: '0.375rem 0.75rem',
                fontSize: '0.75rem'
              }}
            >
              Cancel
            </button>
          </div>
        )}
      </div>

      {/* Warning for newly created keys */}
      {newlyCreatedKey && (
        <div style={{
          background: '#fff3cd',
          color: '#856404',
          padding: '0.75rem',
          borderRadius: '6px',
          marginTop: '0.75rem',
          fontSize: '0.875rem',
          border: '1px solid #ffeaa7'
        }}>
          <strong>⚠️ Important:</strong> This is the only time you&apos;ll see this key. Make sure to copy and store it securely!
        </div>
      )}
    </div>
  );
}