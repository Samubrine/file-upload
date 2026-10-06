import React from 'react';
import { useAuth } from '../context/AuthContext';

export type TabType = 'home' | 'files' | 'shared' | 'benchmarks' | 'account';

interface LayoutProps {
  currentTab: TabType;
  onTabChange: (tab: TabType) => void;
  children: React.ReactNode;
}

export const Layout: React.FC<LayoutProps> = ({ currentTab, onTabChange, children }) => {
  const { user, logout } = useAuth();

  const navItems: { id: TabType; label: string; icon: string }[] = [
    { id: 'home', label: 'Public Catalog', icon: '🌐' },
    { id: 'files', label: 'My Vault', icon: '📁' },
    { id: 'shared', label: 'Shared Files', icon: '👥' },
    { id: 'benchmarks', label: '14-Cipher Benchmark', icon: '📊' },
    { id: 'account', label: 'Account & Quota', icon: '👤' },
  ];

  return (
    <div style={{ display: 'flex', minHeight: '100vh', backgroundColor: 'var(--color-background)' }}>
      {/* Sidebar for Desktop */}
      <aside
        style={{
          width: '240px',
          backgroundColor: 'var(--color-surface)',
          borderRight: '1px solid var(--color-border)',
          display: 'flex',
          flexDirection: 'column',
          position: 'sticky',
          top: 0,
          height: '100vh',
          zIndex: 20,
        }}
      >
        <div style={{ padding: '24px 20px', borderBottom: '1px solid var(--color-border)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span style={{ fontSize: '24px' }}>🔐</span>
            <div>
              <h1 style={{ fontSize: '18px', fontWeight: 700, color: 'var(--color-text)', lineHeight: 1.2 }}>
                CipherVault
              </h1>
              <p style={{ fontSize: '12px', color: 'var(--color-secondary-text)' }}>v1.0 • 14 Encrypted Replicas</p>
            </div>
          </div>
        </div>

        <nav style={{ flex: 1, padding: '16px 12px', display: 'flex', flexDirection: 'column', gap: '4px' }}>
          {navItems.map((item) => {
            const isActive = currentTab === item.id;
            return (
              <button
                key={item.id}
                onClick={() => onTabChange(item.id)}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '12px',
                  padding: '10px 14px',
                  borderRadius: 'var(--radius-control)',
                  fontSize: '14px',
                  fontWeight: isActive ? 600 : 500,
                  color: isActive ? 'var(--color-primary)' : 'var(--color-text)',
                  backgroundColor: isActive ? '#EFF6FF' : 'transparent',
                  textAlign: 'left',
                  width: '100%',
                  transition: 'background-color var(--duration-ms)',
                }}
              >
                <span>{item.icon}</span>
                <span>{item.label}</span>
              </button>
            );
          })}
        </nav>

        {user && (
          <div style={{ padding: '16px 20px', borderTop: '1px solid var(--color-border)', backgroundColor: '#F8FAFC' }}>
            <div style={{ marginBottom: '8px' }}>
              <div style={{ fontSize: '12px', color: 'var(--color-secondary-text)' }}>Logged in as</div>
              <div style={{ fontSize: '14px', fontWeight: 600, color: 'var(--color-text)' }}>@{user.username}</div>
            </div>
            <button
              onClick={logout}
              style={{
                fontSize: '13px',
                color: 'var(--color-danger)',
                fontWeight: 500,
                display: 'inline-flex',
                alignItems: 'center',
                gap: '6px',
                padding: '4px 0',
              }}
            >
              Sign Out
            </button>
          </div>
        )}
      </aside>

      {/* Main Content Area */}
      <main style={{ flex: 1, display: 'flex', flexDirection: 'column', minWidth: 0 }}>
        <header
          style={{
            height: '64px',
            backgroundColor: 'var(--color-surface)',
            borderBottom: '1px solid var(--color-border)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            padding: '0 24px',
          }}
        >
          <div style={{ fontSize: '18px', fontWeight: 600 }}>
            {navItems.find((i) => i.id === currentTab)?.label}
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
            <span
              style={{
                fontSize: '12px',
                padding: '4px 10px',
                backgroundColor: '#F1F5F9',
                borderRadius: '9999px',
                border: '1px solid var(--color-border)',
                color: 'var(--color-secondary-text)',
              }}
            >
              AES-256-CTR Default • Server-Side EtM
            </span>
          </div>
        </header>

        <div
          style={{
            flex: 1,
            padding: '24px',
            maxWidth: 'var(--max-content-width)',
            width: '100%',
            margin: '0 auto',
          }}
        >
          {children}
        </div>
      </main>
    </div>
  );
};

