import { useState, useEffect } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import { useAuth } from '../hooks/useAuth';
import { ApiKeyManagement } from '../components/apikeys';
import { UsageTracking } from '../components/usage';
import { Dashboard } from '../components/dashboard';
import { useValidateToken } from '../hooks/api/auth';
import type { components } from '../generated/api';

type UserInfo = components['schemas']['Model']; // The /auth/me endpoint returns Model schema
import { LogOut, User, Key, Activity, Settings } from 'lucide-react';

export function DashboardPage() {
  const { token, provider, user, logout } = useAuth();
  const location = useLocation();
  const navigate = useNavigate();
  const { data: userInfo } = useValidateToken(token || undefined);

  const [userInfoState, setUserInfoState] = useState<UserInfo | null>(null);

  // Determine active tab from URL
  const getActiveTabFromPath = (pathname: string): 'dashboard' | 'api-keys' | 'usage' => {
    if (pathname.includes('/api-keys')) return 'api-keys';
    if (pathname.includes('/usage')) return 'usage';
    return 'dashboard';
  };

  const [activeTab, setActiveTab] = useState<'dashboard' | 'api-keys' | 'usage'>(
    getActiveTabFromPath(location.pathname)
  );

  // Update active tab when URL changes
  useEffect(() => {
    const newTab = getActiveTabFromPath(location.pathname);
    setActiveTab(newTab);
  }, [location.pathname]);

  // Update local state when userInfo from React Query changes
  useEffect(() => {
    if (userInfo) {
      // Convert null to undefined for compatibility with UserInfo type
      const adaptedUserInfo: UserInfo = {
        ...userInfo,
        display_name: userInfo.display_name ?? undefined,
        last_login: userInfo.last_login ?? undefined,
      };
      setUserInfoState(adaptedUserInfo);
    }
  }, [userInfo]);

  // Listen for tab switching events from the Dashboard component
  useEffect(() => {
    const handleTabSwitch = (event: CustomEvent) => {
      const tab = event.detail;
      let path = '/dashboard/overview';
      if (tab === 'api-keys') path = '/dashboard/api-keys';
      if (tab === 'usage') path = '/dashboard/usage';
      navigate(path);
    };

    window.addEventListener('switchTab', handleTabSwitch as EventListener);

    return () => {
      window.removeEventListener('switchTab', handleTabSwitch as EventListener);
    };
  }, [navigate]);

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
              Welcome back, {userInfoState?.display_name || userInfoState?.email || user}!
            </h3>
            <p>
              <strong>Email:</strong> {userInfoState?.email || user}
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
            onClick={() => navigate('/dashboard/overview')}
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
            onClick={() => navigate('/dashboard/api-keys')}
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
            onClick={() => navigate('/dashboard/usage')}
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
