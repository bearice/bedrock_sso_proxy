import { useState, useCallback } from 'react';
import { CreateApiKeyRequest } from '../../types/auth';
import { X, Key, Calendar, AlertCircle } from 'lucide-react';

interface CreateApiKeyModalProps {
  isOpen: boolean;
  onClose: () => void;
  onCreate: (request: CreateApiKeyRequest) => Promise<void>;
  isCreating: boolean;
}

export function CreateApiKeyModal({ isOpen, onClose, onCreate, isCreating }: CreateApiKeyModalProps) {
  const [name, setName] = useState('');
  const [expiresInDays, setExpiresInDays] = useState<number | undefined>(90);
  const [errors, setErrors] = useState<{ name?: string; expiresInDays?: string }>({});

  const validateForm = useCallback(() => {
    const newErrors: { name?: string; expiresInDays?: string } = {};

    if (!name.trim()) {
      newErrors.name = 'API key name is required';
    } else if (name.trim().length > 100) {
      newErrors.name = 'API key name must be 100 characters or less';
    }

    if (expiresInDays !== undefined && (expiresInDays < 1 || expiresInDays > 365)) {
      newErrors.expiresInDays = 'Expiration must be between 1 and 365 days';
    }

    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  }, [name, expiresInDays]);

  const handleSubmit = useCallback(async (e: React.FormEvent) => {
    e.preventDefault();
    
    if (!validateForm()) {
      return;
    }

    try {
      await onCreate({
        name: name.trim(),
        expires_in_days: expiresInDays,
      });
      
      // Reset form on success
      setName('');
      setExpiresInDays(90);
      setErrors({});
    } catch (error) {
      console.error('Failed to create API key:', error);
    }
  }, [name, expiresInDays, onCreate, validateForm]);

  const handleClose = useCallback(() => {
    if (!isCreating) {
      setName('');
      setExpiresInDays(90);
      setErrors({});
      onClose();
    }
  }, [isCreating, onClose]);

  if (!isOpen) return null;

  return (
    <div style={{
      position: 'fixed',
      top: 0,
      left: 0,
      right: 0,
      bottom: 0,
      backgroundColor: 'rgba(0, 0, 0, 0.5)',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      zIndex: 1000,
    }}>
      <div style={{
        backgroundColor: 'white',
        borderRadius: '8px',
        padding: '1.5rem',
        width: '90%',
        maxWidth: '500px',
        maxHeight: '90vh',
        overflowY: 'auto',
        boxShadow: '0 10px 25px rgba(0, 0, 0, 0.2)',
      }}>
        {/* Header */}
        <div style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          marginBottom: '1.5rem',
          paddingBottom: '1rem',
          borderBottom: '1px solid #e9ecef'
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <Key size={24} style={{ color: '#4f46e5' }} />
            <h2 style={{ margin: 0, fontSize: '1.5rem' }}>Create API Key</h2>
          </div>
          <button
            onClick={handleClose}
            disabled={isCreating}
            style={{
              background: 'none',
              border: 'none',
              cursor: isCreating ? 'not-allowed' : 'pointer',
              opacity: isCreating ? 0.5 : 1,
            }}
          >
            <X size={24} style={{ color: '#6c757d' }} />
          </button>
        </div>

        {/* Form */}
        <form onSubmit={handleSubmit}>
          {/* Name Field */}
          <div style={{ marginBottom: '1.5rem' }}>
            <label htmlFor="api-key-name" style={{
              display: 'block',
              marginBottom: '0.5rem',
              fontWeight: '500',
              fontSize: '0.875rem'
            }}>
              API Key Name *
            </label>
            <input
              id="api-key-name"
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="e.g., My Application Key"
              disabled={isCreating}
              style={{
                width: '100%',
                padding: '0.75rem',
                border: `1px solid ${errors.name ? '#dc3545' : '#ced4da'}`,
                borderRadius: '4px',
                fontSize: '1rem',
                backgroundColor: isCreating ? '#f8f9fa' : 'white',
                opacity: isCreating ? 0.7 : 1,
                boxSizing: 'border-box',
              }}
            />
            {errors.name && (
              <div style={{
                display: 'flex',
                alignItems: 'center',
                gap: '0.25rem',
                color: '#dc3545',
                fontSize: '0.875rem',
                marginTop: '0.25rem'
              }}>
                <AlertCircle size={14} />
                {errors.name}
              </div>
            )}
            <div style={{
              fontSize: '0.75rem',
              color: '#6c757d',
              marginTop: '0.25rem'
            }}>
              Choose a descriptive name to identify this key&apos;s purpose
            </div>
          </div>

          {/* Expiration Field */}
          <div style={{ marginBottom: '1.5rem' }}>
            <label htmlFor="api-key-expiration" style={{
              display: 'block',
              marginBottom: '0.5rem',
              fontWeight: '500',
              fontSize: '0.875rem'
            }}>
              <Calendar size={16} style={{ marginRight: '0.25rem', verticalAlign: 'text-bottom' }} />
              Expiration
            </label>
            <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
              <input
                id="api-key-expiration"
                type="number"
                value={expiresInDays || ''}
                onChange={(e) => setExpiresInDays(e.target.value ? parseInt(e.target.value) : undefined)}
                placeholder="90"
                min="1"
                max="365"
                disabled={isCreating}
                style={{
                  width: '100px',
                  padding: '0.75rem',
                  border: `1px solid ${errors.expiresInDays ? '#dc3545' : '#ced4da'}`,
                  borderRadius: '4px',
                  fontSize: '1rem',
                  backgroundColor: isCreating ? '#f8f9fa' : 'white',
                  opacity: isCreating ? 0.7 : 1,
                  boxSizing: 'border-box',
                }}
              />
              <span style={{ fontSize: '0.875rem', color: '#6c757d' }}>days</span>
              <button
                type="button"
                onClick={() => setExpiresInDays(undefined)}
                disabled={isCreating}
                style={{
                  background: 'none',
                  border: '1px solid #6c757d',
                  padding: '0.5rem 0.75rem',
                  borderRadius: '4px',
                  fontSize: '0.75rem',
                  cursor: isCreating ? 'not-allowed' : 'pointer',
                  opacity: isCreating ? 0.5 : 1,
                }}
              >
                Never expires
              </button>
            </div>
            {errors.expiresInDays && (
              <div style={{
                display: 'flex',
                alignItems: 'center',
                gap: '0.25rem',
                color: '#dc3545',
                fontSize: '0.875rem',
                marginTop: '0.25rem'
              }}>
                <AlertCircle size={14} />
                {errors.expiresInDays}
              </div>
            )}
            <div style={{
              fontSize: '0.75rem',
              color: '#6c757d',
              marginTop: '0.25rem'
            }}>
              {expiresInDays 
                ? `Key will expire in ${expiresInDays} days`
                : 'Key will never expire (not recommended for production)'
              }
            </div>
          </div>

          {/* Quick Expiration Presets */}
          <div style={{ marginBottom: '1.5rem' }}>
            <div style={{
              fontSize: '0.875rem',
              color: '#6c757d',
              marginBottom: '0.5rem'
            }}>
              Quick presets:
            </div>
            <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
              {[30, 90, 180, 365].map((days) => (
                <button
                  key={days}
                  type="button"
                  onClick={() => setExpiresInDays(days)}
                  disabled={isCreating}
                  style={{
                    background: expiresInDays === days ? '#4f46e5' : 'white',
                    color: expiresInDays === days ? 'white' : '#6c757d',
                    border: '1px solid #ced4da',
                    padding: '0.25rem 0.5rem',
                    borderRadius: '4px',
                    fontSize: '0.75rem',
                    cursor: isCreating ? 'not-allowed' : 'pointer',
                    opacity: isCreating ? 0.5 : 1,
                  }}
                >
                  {days} days
                </button>
              ))}
            </div>
          </div>

          {/* Security Warning */}
          <div style={{
            background: '#fff3cd',
            border: '1px solid #ffeaa7',
            borderRadius: '6px',
            padding: '1rem',
            marginBottom: '1.5rem',
            fontSize: '0.875rem',
            color: '#856404'
          }}>
            <div style={{ fontWeight: '500', marginBottom: '0.5rem' }}>
              🔐 Security Guidelines:
            </div>
            <ul style={{ margin: 0, paddingLeft: '1.2rem' }}>
              <li>This key will have the same permissions as your account</li>
              <li>You&apos;ll only see the full key once - copy it immediately</li>
              <li>Store it securely and never share it publicly</li>
              <li>Consider setting an expiration date for better security</li>
            </ul>
          </div>

          {/* Actions */}
          <div style={{
            display: 'flex',
            gap: '0.75rem',
            justifyContent: 'flex-end',
            paddingTop: '1rem',
            borderTop: '1px solid #e9ecef'
          }}>
            <button
              type="button"
              onClick={handleClose}
              disabled={isCreating}
              className="btn"
              style={{
                background: '#6c757d',
                color: 'white',
                border: '1px solid #6c757d',
                padding: '0.75rem 1.5rem',
                opacity: isCreating ? 0.5 : 1,
                cursor: isCreating ? 'not-allowed' : 'pointer',
              }}
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={isCreating || !name.trim()}
              className="btn"
              style={{
                background: '#4f46e5',
                color: 'white',
                border: '1px solid #4f46e5',
                padding: '0.75rem 1.5rem',
                opacity: (isCreating || !name.trim()) ? 0.5 : 1,
                cursor: (isCreating || !name.trim()) ? 'not-allowed' : 'pointer',
              }}
            >
              {isCreating ? 'Creating...' : 'Create API Key'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}