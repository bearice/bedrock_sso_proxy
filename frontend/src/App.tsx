import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { LoginPage } from './pages/LoginPage';
import { DashboardPage } from './pages/DashboardPage';
import { CallbackPage } from './pages/CallbackPage';
import { AuthProvider } from './contexts/AuthContext';
import { useAuth } from './hooks/useAuth';
import { appLogger } from './utils/logger';
import './App.css';

function AppContent() {
  const { isAuthenticated, loading } = useAuth();

  appLogger.debug('Render', { isAuthenticated, loading });

  if (loading) {
    appLogger.debug('Showing loading screen');
    return (
      <div className="loading-container">
        <div className="loading-spinner"></div>
        <p>Loading...</p>
      </div>
    );
  }

  return (
    <Router>
      <div className="app">
        <Routes>
          <Route
            path="/"
            element={
              isAuthenticated ? (
                <Navigate to="/dashboard/overview" replace />
              ) : (
                <Navigate to="/login" replace />
              )
            }
          />
          <Route path="/login" element={<LoginPage />} />
          <Route path="/callback" element={<CallbackPage />} />
          <Route
            path="/dashboard"
            element={
              isAuthenticated
                ? (() => {
                    appLogger.debug('Rendering DashboardPage');
                    return <Navigate to="/dashboard/overview" replace />;
                  })()
                : (() => {
                    appLogger.debug('Redirecting to login from dashboard route');
                    return <Navigate to="/login" replace />;
                  })()
            }
          />
          <Route
            path="/dashboard/overview"
            element={
              isAuthenticated
                ? (() => {
                    appLogger.debug('Rendering DashboardPage - overview');
                    return <DashboardPage />;
                  })()
                : (() => {
                    appLogger.debug('Redirecting to login from dashboard route');
                    return <Navigate to="/login" replace />;
                  })()
            }
          />
          <Route
            path="/dashboard/api-keys"
            element={
              isAuthenticated
                ? (() => {
                    appLogger.debug('Rendering DashboardPage - api-keys');
                    return <DashboardPage />;
                  })()
                : (() => {
                    appLogger.debug('Redirecting to login from dashboard route');
                    return <Navigate to="/login" replace />;
                  })()
            }
          />
          <Route
            path="/dashboard/usage"
            element={
              isAuthenticated
                ? (() => {
                    appLogger.debug('Rendering DashboardPage - usage');
                    return <DashboardPage />;
                  })()
                : (() => {
                    appLogger.debug('Redirecting to login from dashboard route');
                    return <Navigate to="/login" replace />;
                  })()
            }
          />
          <Route
            path="*"
            element={
              <div className="container">
                <div className="card">
                  <h1>404 - Page Not Found</h1>
                  <p>The page you&apos;re looking for doesn&apos;t exist.</p>
                  <a href="/dashboard/overview" className="btn btn-primary">
                    Go Home
                  </a>
                </div>
              </div>
            }
          />
        </Routes>
      </div>
    </Router>
  );
}

function App() {
  return (
    <AuthProvider>
      <AppContent />
    </AuthProvider>
  );
}

export default App;
