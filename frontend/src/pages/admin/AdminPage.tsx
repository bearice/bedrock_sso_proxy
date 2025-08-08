import { useState, useEffect } from 'react';
import { Routes, Route, useLocation, useNavigate } from 'react-router-dom';
import { UserManagement } from '../../components/admin/UserManagement';
import { SystemUsage } from '../../components/admin/SystemUsage';
import { CostManagement } from '../../components/admin/CostManagement';
import { AuditLogs } from '../../components/admin/AuditLogs';
import { Users, BarChart2, DollarSign, ClipboardList } from 'lucide-react';

export function AdminPage() {
  const location = useLocation();
  const navigate = useNavigate();

  type AdminTab = 'users' | 'usage' | 'costs' | 'audits';

  const getActiveTabFromPath = (pathname: string): AdminTab => {
    if (pathname.includes('/usage')) return 'usage';
    if (pathname.includes('/costs')) return 'costs';
    if (pathname.includes('/audits')) return 'audits';
    return 'users';
  };

  const [activeTab, setActiveTab] = useState<AdminTab>(getActiveTabFromPath(location.pathname));

  useEffect(() => {
    setActiveTab(getActiveTabFromPath(location.pathname));
  }, [location.pathname]);

  return (
    <div className="container">
      <div className="card">
        <h1>Admin Dashboard</h1>
        <p>Welcome to the admin dashboard. Here you can manage users, view system usage, and more.</p>
      </div>

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
            onClick={() => navigate('/admin/users')}
            style={{
              flex: 1,
              padding: '1rem 1.5rem',
              border: 'none',
              background: activeTab === 'users' ? '#4f46e5' : 'transparent',
              color: activeTab === 'users' ? 'white' : '#6c757d',
              cursor: 'pointer',
              fontSize: '1rem',
              fontWeight: 500,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              gap: '0.5rem',
              transition: 'all 0.2s ease',
            }}
          >
            <Users size={18} />
            User Management
          </button>
          <button
            onClick={() => navigate('/admin/usage')}
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
          >
            <BarChart2 size={18} />
            System Usage
          </button>
          <button
            onClick={() => navigate('/admin/costs')}
            style={{
              flex: 1,
              padding: '1rem 1.5rem',
              border: 'none',
              background: activeTab === 'costs' ? '#4f46e5' : 'transparent',
              color: activeTab === 'costs' ? 'white' : '#6c757d',
              cursor: 'pointer',
              fontSize: '1rem',
              fontWeight: 500,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              gap: '0.5rem',
              transition: 'all 0.2s ease',
            }}
          >
            <DollarSign size={18} />
            Cost Management
          </button>
          <button
            onClick={() => navigate('/admin/audits')}
            style={{
              flex: 1,
              padding: '1rem 1.5rem',
              border: 'none',
              background: activeTab === 'audits' ? '#4f46e5' : 'transparent',
              color: activeTab === 'audits' ? 'white' : '#6c757d',
              cursor: 'pointer',
              fontSize: '1rem',
              fontWeight: 500,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              gap: '0.5rem',
              transition: 'all 0.2s ease',
            }}
          >
            <ClipboardList size={18} />
            Audit Logs
          </button>
        </div>
      </div>

      <Routes>
        <Route path="users" element={<UserManagement />} />
        <Route path="usage" element={<SystemUsage />} />
        <Route path="costs" element={<CostManagement />} />
        <Route path="audits" element={<AuditLogs />} />
      </Routes>
    </div>
  );
}
