import { useState, useEffect } from 'react';
import { useAuth } from '../hooks/useAuth';
import { ApiKeyManagement } from '../components/apikeys';
import { UsageTracking } from '../components/usage';
import { Dashboard } from '../components/dashboard';
import { authApi } from '../services/api';
import {
  LogOut,
  User,
  Key,
  Activity,
  Settings,
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
  const { token, provider, user, logout } =
    useAuth();

  const [userInfo, setUserInfo] = useState<UserInfo | null>(null);
  const [activeTab, setActiveTab] = useState<'dashboard' | 'api-keys' | 'usage'>('dashboard');

  // Fetch user info from /auth/me API with 401 handling
  useEffect(() => {
    const fetchUserInfo = async () => {
      if (!token) return;

      try {
        const data = await authApi.validateToken(token);
        if (data) {
          setUserInfo(data);
        }
      } catch (error) {
        console.error('Failed to fetch user info:', error);
      }
    };

    fetchUserInfo();
  }, [token]);

  // Listen for tab switching events from the Dashboard component
  useEffect(() => {
    const handleTabSwitch = (event: CustomEvent) => {
      setActiveTab(event.detail);
    };

    window.addEventListener('switchTab', handleTabSwitch as EventListener);
    
    return () => {
      window.removeEventListener('switchTab', handleTabSwitch as EventListener);
    };
  }, []);

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
              <strong>OAuth Provider:</strong> {getProviderDisplayName(provider || '')}
            </p>
          </div>
          <div>
            <button onClick={logout} className="btn btn-danger" style={{ marginLeft: '1rem' }}>
              <LogOut size={16} />
              Logout
            </button>
          </div>
        </div>
      </div>

      {/* Navigation Tabs */}
      <div
        style={{
          background: 'white',
          borderRadius: '12px',
          marginBottom: '1.5rem',
          border: '1px solid #e9ecef',
          overflow: 'hidden',
        }}
      >
        <div
          style={{
            display: 'flex',
            borderBottom: '1px solid #e9ecef',
          }}
        >
          <button
            onClick={() => setActiveTab('dashboard')}
            style={{
              flex: 1,
              padding: '1rem 1.5rem',
              border: 'none',
              background: activeTab === 'dashboard' ? '#4f46e5' : 'transparent',
              color: activeTab === 'dashboard' ? 'white' : '#6c757d',
              cursor: 'pointer',
              fontSize: '1rem',
              fontWeight: 500,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              gap: '0.5rem',
              transition: 'all 0.2s ease',
            }}
            onMouseEnter={(e) => {
              if (activeTab !== 'dashboard') {
                e.currentTarget.style.background = '#f8f9fa';
              }
            }}
            onMouseLeave={(e) => {
              if (activeTab !== 'dashboard') {
                e.currentTarget.style.background = 'transparent';
              }
            }}
          >
            <Settings size={18} />
            Dashboard
          </button>
          <button
            onClick={() => setActiveTab('api-keys')}
            style={{
              flex: 1,
              padding: '1rem 1.5rem',
              border: 'none',
              background: activeTab === 'api-keys' ? '#4f46e5' : 'transparent',
              color: activeTab === 'api-keys' ? 'white' : '#6c757d',
              cursor: 'pointer',
              fontSize: '1rem',
              fontWeight: 500,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              gap: '0.5rem',
              transition: 'all 0.2s ease',
            }}
            onMouseEnter={(e) => {
              if (activeTab !== 'api-keys') {
                e.currentTarget.style.background = '#f8f9fa';
              }
            }}
            onMouseLeave={(e) => {
              if (activeTab !== 'api-keys') {
                e.currentTarget.style.background = 'transparent';
              }
            }}
          >
            <Key size={18} />
            API Keys
          </button>
          <button
            onClick={() => setActiveTab('usage')}
            style={{
              flex: 1,
              padding: '1rem 1.5rem',
              border: 'none',
              background: activeTab === 'usage' ? '#4f46e5' : 'transparent',
              color: activeTab === 'usage' ? 'white' : '#6c757d',
              cursor: 'pointer',
              fontSize: '1rem',
              fontWeight: 500,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              gap: '0.5rem',
              transition: 'all 0.2s ease',
            }}
            onMouseEnter={(e) => {
              if (activeTab !== 'usage') {
                e.currentTarget.style.background = '#f8f9fa';
              }
            }}
            onMouseLeave={(e) => {
              if (activeTab !== 'usage') {
                e.currentTarget.style.background = 'transparent';
              }
            }}
          >
            <Activity size={18} />
            Usage Tracking
          </button>
        </div>
      </div>

      {/* Tab Content */}
      {activeTab === 'dashboard' && <Dashboard />}

      {/* API Keys Tab */}
      {activeTab === 'api-keys' && <ApiKeyManagement />}

      {/* Usage Tracking Tab */}
      {activeTab === 'usage' && <UsageTracking />}
    </div>
  );
}