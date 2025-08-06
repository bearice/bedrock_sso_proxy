import { useState, useCallback } from 'react';
import { useAuth } from '../../hooks/useAuth';
import { useApiKeys, useCreateApiKey, useRevokeApiKey } from '../../hooks/api';
import type { components } from '../../generated/api';

type CreateApiKeyRequest = components['schemas']['CreateApiKeyRequest'];
import { ApiKeyCard } from './ApiKeyCard';
import { CreateApiKeyModal } from './CreateApiKeyModal';
import { Key, Plus, RefreshCw, AlertCircle, CheckCircle } from 'lucide-react';

export function ApiKeyManagement() {
  const { token } = useAuth();
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [success, setSuccess] = useState<string | null>(null);
  const [newlyCreatedKey, setNewlyCreatedKey] = useState<{ id: number; key: string } | null>(null);

  // Use React Query hooks
  const {
    data: apiKeys = [],
    isLoading,
    error: loadError,
    refetch: loadApiKeys,
  } = useApiKeys(token || undefined);
  const createApiKeyMutation = useCreateApiKey(token || undefined);
  const revokeApiKeyMutation = useRevokeApiKey(token || undefined);

  const error =
    loadError?.message ||
    createApiKeyMutation.error?.message ||
    revokeApiKeyMutation.error?.message ||
    null;

  // Create new API key
  const handleCreateApiKey = useCallback(
    async (request: CreateApiKeyRequest) => {
      try {
        const response = await createApiKeyMutation.mutateAsync(request);
        setNewlyCreatedKey({ id: response.id, key: response.key });
        setShowCreateModal(false);
        setSuccess(`API key "${response.name}" created successfully!`);

        // Clear success message after 5 seconds
        setTimeout(() => setSuccess(null), 5000);
      } catch (err) {
        console.error('Failed to create API key:', err);
      }
    },
    [createApiKeyMutation]
  );

  // Revoke API key
  const handleRevokeApiKey = useCallback(
    async (keyId: number) => {
      try {
        // Find the key to get its name and hash for the API call
        const keyToRevoke = apiKeys.find((key) => key.id === keyId);
        if (!keyToRevoke) {
          console.error('API key not found');
          return;
        }

        await revokeApiKeyMutation.mutateAsync(keyToRevoke.key_hash);

        // Clear newly created key if it was revoked
        if (newlyCreatedKey?.id === keyId) {
          setNewlyCreatedKey(null);
        }

        setSuccess(`API key "${keyToRevoke.name}" revoked successfully!`);

        // Clear success message after 3 seconds
        setTimeout(() => setSuccess(null), 3000);
      } catch (err) {
        console.error('Failed to revoke API key:', err);
      }
    },
    [apiKeys, revokeApiKeyMutation, newlyCreatedKey]
  );

  // Clear messages
  const clearSuccess = useCallback(() => setSuccess(null), []);

  if (!token) {
    return (
      <div style={{ textAlign: 'center', padding: '2rem' }}>
        <AlertCircle size={48} style={{ color: '#dc3545', margin: '0 auto 1rem' }} />
        <h3>Authentication Required</h3>
        <p>Please log in to manage your API keys.</p>
      </div>
    );
  }

  return (
    <div>
      {/* Header */}
      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          marginBottom: '1.5rem',
        }}
      >
        <div>
          <h2 style={{ margin: 0, display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <Key size={24} />
            API Key Management
          </h2>
          <p style={{ margin: '0.5rem 0 0 0', color: '#374151', fontWeight: '500' }}>
            Create and manage API keys for programmatic access to the Bedrock proxy
          </p>
        </div>
        <div style={{ display: 'flex', gap: '0.75rem' }}>
          <button
            onClick={() => loadApiKeys()}
            disabled={isLoading}
            className="btn btn-secondary"
            style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}
          >
            <RefreshCw size={16} className={isLoading ? 'loading-spinner' : ''} />
            Refresh
          </button>
          <button
            onClick={() => setShowCreateModal(true)}
            className="btn"
            style={{
              background: '#4f46e5',
              color: 'white',
              border: '1px solid #4f46e5',
              display: 'flex',
              alignItems: 'center',
              gap: '0.5rem',
            }}
          >
            <Plus size={16} />
            Create API Key
          </button>
        </div>
      </div>

      {/* Success Message */}
      {success && (
        <div
          style={{
            background: '#d1edff',
            border: '1px solid #0084ff',
            borderRadius: '6px',
            padding: '0.75rem',
            marginBottom: '1rem',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <CheckCircle size={16} style={{ color: '#0084ff' }} />
            <span style={{ color: '#0056b3' }}>{success}</span>
          </div>
          <button
            onClick={clearSuccess}
            style={{
              background: 'none',
              border: 'none',
              color: '#0056b3',
              cursor: 'pointer',
              fontSize: '1.2rem',
            }}
          >
            ×
          </button>
        </div>
      )}

      {/* Error Message */}
      {error && (
        <div
          style={{
            background: '#f8d7da',
            border: '1px solid #f5c6cb',
            borderRadius: '6px',
            padding: '0.75rem',
            marginBottom: '1rem',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <AlertCircle size={16} style={{ color: '#721c24' }} />
            <span style={{ color: '#721c24' }}>{error}</span>
          </div>
          <button
            onClick={() => {
              /* Error is cleared automatically by React Query */
            }}
            style={{
              background: 'none',
              border: 'none',
              color: '#721c24',
              cursor: 'pointer',
              fontSize: '1.2rem',
            }}
          >
            ×
          </button>
        </div>
      )}

      {/* Loading State */}
      {isLoading && (
        <div style={{ textAlign: 'center', padding: '2rem' }}>
          <RefreshCw size={32} className="loading-spinner" style={{ margin: '0 auto 1rem' }} />
          <p>Loading API keys...</p>
        </div>
      )}

      {/* API Keys List */}
      {!isLoading && (
        <>
          {apiKeys.length === 0 ? (
            <div
              style={{
                textAlign: 'center',
                padding: '3rem 1rem',
                border: '2px dashed #ced4da',
                borderRadius: '8px',
                color: '#6c757d',
              }}
            >
              <Key size={48} style={{ margin: '0 auto 1rem', opacity: 0.5 }} />
              <h3 style={{ margin: '0 0 0.5rem 0' }}>No API Keys</h3>
              <p style={{ margin: '0 0 1.5rem 0' }}>
                You haven&apos;t created any API keys yet. Create your first API key to get started
                with programmatic access.
              </p>
              <button
                onClick={() => setShowCreateModal(true)}
                className="btn"
                style={{
                  background: '#4f46e5',
                  color: 'white',
                  border: '1px solid #4f46e5',
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: '0.5rem',
                }}
              >
                <Plus size={16} />
                Create Your First API Key
              </button>
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
              {apiKeys.map((apiKey) => (
                <ApiKeyCard
                  key={apiKey.id}
                  apiKey={apiKey}
                  onRevoke={handleRevokeApiKey}
                  newlyCreatedKey={
                    newlyCreatedKey?.id === apiKey.id ? newlyCreatedKey.key : undefined
                  }
                />
              ))}
            </div>
          )}

          {/* Statistics */}
          {apiKeys.length > 0 && (
            <div
              style={{
                marginTop: '2rem',
                padding: '1rem',
                background: '#f8f9fa',
                borderRadius: '8px',
                display: 'flex',
                justifyContent: 'space-around',
                fontSize: '0.875rem',
                color: '#6c757d',
              }}
            >
              <div style={{ textAlign: 'center' }}>
                <div style={{ fontSize: '1.5rem', fontWeight: 'bold', color: '#28a745' }}>
                  {
                    apiKeys.filter(
                      (key) =>
                        !key.revoked_at &&
                        (!key.expires_at || new Date(key.expires_at) > new Date())
                    ).length
                  }
                </div>
                <div>Active Keys</div>
              </div>
              <div style={{ textAlign: 'center' }}>
                <div style={{ fontSize: '1.5rem', fontWeight: 'bold', color: '#fd7e14' }}>
                  {
                    apiKeys.filter(
                      (key) =>
                        key.expires_at && new Date(key.expires_at) < new Date() && !key.revoked_at
                    ).length
                  }
                </div>
                <div>Expired Keys</div>
              </div>
              <div style={{ textAlign: 'center' }}>
                <div style={{ fontSize: '1.5rem', fontWeight: 'bold', color: '#dc3545' }}>
                  {apiKeys.filter((key) => key.revoked_at).length}
                </div>
                <div>Revoked Keys</div>
              </div>
              <div style={{ textAlign: 'center' }}>
                <div style={{ fontSize: '1.5rem', fontWeight: 'bold', color: '#6c757d' }}>
                  {apiKeys.length}
                </div>
                <div>Total Keys</div>
              </div>
            </div>
          )}
        </>
      )}

      {/* Create API Key Modal */}
      <CreateApiKeyModal
        isOpen={showCreateModal}
        onClose={() => setShowCreateModal(false)}
        onCreate={handleCreateApiKey}
        isCreating={createApiKeyMutation.isPending}
      />
    </div>
  );
}
