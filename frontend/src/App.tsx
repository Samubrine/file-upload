import React, { useState } from 'react';
import type { TabType } from './components/Layout';
import { Layout } from './components/Layout';
import { AuthProvider, useAuth } from './context/AuthContext';
import { Account } from './features/account/Account';
import { Login } from './features/auth/Login';
import { Register } from './features/auth/Register';
import { BenchmarkView } from './features/benchmarks/BenchmarkView';
import { HomeListed } from './features/files/HomeListed';
import { MyFiles } from './features/files/MyFiles';
import { SharedFiles } from './features/files/SharedFiles';
import './styles/theme.css';

const MainApp: React.FC = () => {
  const { user, loading } = useAuth();
  const [authView, setAuthView] = useState<'login' | 'register'>('login');
  const [currentTab, setCurrentTab] = useState<TabType>('files');

  if (loading) {
    return (
      <div
        style={{
          minHeight: '100vh',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          backgroundColor: 'var(--color-background)',
          color: 'var(--color-secondary-text)',
        }}
      >
        <div style={{ textAlign: 'center' }}>
          <div style={{ fontSize: '32px', marginBottom: '12px' }}>🔐</div>
          <div>Loading CipherVault...</div>
        </div>
      </div>
    );
  }

  if (!user) {
    if (authView === 'register') {
      return <Register onSwitchToLogin={() => setAuthView('login')} />;
    }
    return <Login onSwitchToRegister={() => setAuthView('register')} />;
  }

  return (
    <Layout currentTab={currentTab} onTabChange={setCurrentTab}>
      {currentTab === 'home' && <HomeListed />}
      {currentTab === 'files' && <MyFiles />}
      {currentTab === 'shared' && <SharedFiles />}
      {currentTab === 'benchmarks' && <BenchmarkView />}
      {currentTab === 'account' && <Account />}
    </Layout>
  );
};

export const App: React.FC = () => {
  return (
    <AuthProvider>
      <MainApp />
    </AuthProvider>
  );
};

export default App;

