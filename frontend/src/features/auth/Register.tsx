import React, { useEffect, useState } from 'react';
import { api } from '../../api/client';
import { Button } from '../../components/Button';
import { useAuth } from '../../context/AuthContext';

export const Register: React.FC<{ onSwitchToLogin: () => void }> = ({ onSwitchToLogin }) => {
  const { register } = useAuth();
  const [fullName, setFullName] = useState('');
  const [username, setUsername] = useState('');
  const [email, setEmail] = useState('');
  const [birthday, setBirthday] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [noticeText, setNoticeText] = useState('');
  const [noticeAck, setNoticeAck] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  useEffect(() => {
    api.getNotice().then((n) => setNoticeText(n.text)).catch(() => {});
  }, []);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!noticeAck) {
      setError('You must acknowledge the security and privacy notice.');
      return;
    }
    if (password.length < 12) {
      setError('Password must be at least 12 characters.');
      return;
    }

    setError(null);
    setSubmitting(true);
    try {
      await register({
        full_name: fullName,
        username,
        email,
        birthday: birthday || null,
        password,
        notice_version: '1.0',
        notice_acknowledged: true,
      });
    } catch (err: any) {
      setError(err.message || 'Registration failed');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div
      style={{
        minHeight: '100vh',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        padding: '24px',
        backgroundColor: 'var(--color-background)',
      }}
    >
      <div
        style={{
          width: '100%',
          maxWidth: '520px',
          backgroundColor: 'var(--color-surface)',
          borderRadius: 'var(--radius-panel)',
          border: '1px solid var(--color-border)',
          padding: '32px',
          boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.05)',
        }}
      >
        <div style={{ textAlign: 'center', marginBottom: '24px' }}>
          <div style={{ fontSize: '32px', marginBottom: '8px' }}>🔐</div>
          <h1 style={{ fontSize: '24px', fontWeight: 700, color: 'var(--color-text)' }}>Create Account</h1>
          <p style={{ fontSize: '14px', color: 'var(--color-secondary-text)', marginTop: '4px' }}>
            All user data is encrypted across 14 cryptographic variants.
          </p>
        </div>

        {error && (
          <div
            style={{
              padding: '12px 14px',
              backgroundColor: '#FEF2F2',
              border: '1px solid #FECACA',
              borderRadius: 'var(--radius-control)',
              color: 'var(--color-danger)',
              fontSize: '14px',
              marginBottom: '20px',
            }}
          >
            {error}
          </div>
        )}

        <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
          <div>
            <label style={{ display: 'block', fontSize: '14px', fontWeight: 500, marginBottom: '6px' }}>
              Full Name *
            </label>
            <input
              type="text"
              required
              value={fullName}
              onChange={(e) => setFullName(e.target.value)}
              placeholder="e.g. Alice Wonderland"
              style={{
                width: '100%',
                height: 'var(--input-height)',
                padding: '0 12px',
                borderRadius: 'var(--radius-control)',
                border: '1px solid var(--color-border)',
                outline: 'none',
              }}
            />
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
            <div>
              <label style={{ display: 'block', fontSize: '14px', fontWeight: 500, marginBottom: '6px' }}>
                Username *
              </label>
              <input
                type="text"
                required
                pattern="^[a-z0-9_]{3,32}$"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="alice_wonder"
                style={{
                  width: '100%',
                  height: 'var(--input-height)',
                  padding: '0 12px',
                  borderRadius: 'var(--radius-control)',
                  border: '1px solid var(--color-border)',
                  outline: 'none',
                }}
              />
              <span style={{ fontSize: '11px', color: 'var(--color-secondary-text)' }}>3-32 lowercase/digits</span>
            </div>

            <div>
              <label style={{ display: 'block', fontSize: '14px', fontWeight: 500, marginBottom: '6px' }}>
                Email *
              </label>
              <input
                type="email"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="alice@example.com"
                style={{
                  width: '100%',
                  height: 'var(--input-height)',
                  padding: '0 12px',
                  borderRadius: 'var(--radius-control)',
                  border: '1px solid var(--color-border)',
                  outline: 'none',
                }}
              />
            </div>
          </div>

          <div>
            <label style={{ display: 'block', fontSize: '14px', fontWeight: 500, marginBottom: '6px' }}>
              Birthday <span style={{ fontWeight: 400, color: 'var(--color-secondary-text)' }}>(Optional)</span>
            </label>
            <input
              type="date"
              value={birthday}
              onChange={(e) => setBirthday(e.target.value)}
              max={new Date().toISOString().split('T')[0]}
              style={{
                width: '100%',
                height: 'var(--input-height)',
                padding: '0 12px',
                borderRadius: 'var(--radius-control)',
                border: '1px solid var(--color-border)',
                outline: 'none',
              }}
            />
          </div>

          <div>
            <label style={{ display: 'block', fontSize: '14px', fontWeight: 500, marginBottom: '6px' }}>
              Password *
            </label>
            <div style={{ position: 'relative' }}>
              <input
                type={showPassword ? 'text' : 'password'}
                required
                minLength={12}
                maxLength={128}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="At least 12 characters"
                style={{
                  width: '100%',
                  height: 'var(--input-height)',
                  padding: '0 44px 0 12px',
                  borderRadius: 'var(--radius-control)',
                  border: '1px solid var(--color-border)',
                  outline: 'none',
                }}
              />
              <button
                type="button"
                onClick={() => setShowPassword(!showPassword)}
                style={{
                  position: 'absolute',
                  right: '12px',
                  top: '50%',
                  transform: 'translateY(-50%)',
                  color: 'var(--color-secondary-text)',
                  fontSize: '13px',
                }}
              >
                {showPassword ? 'Hide' : 'Show'}
              </button>
            </div>
            <span style={{ fontSize: '11px', color: 'var(--color-secondary-text)' }}>
              Salted Argon2id hash (memory ≥ 19 MiB, iterations ≥ 2)
            </span>
          </div>

          {/* Privacy Notice Disclosure */}
          <div
            style={{
              padding: '12px',
              backgroundColor: '#F8FAFC',
              borderRadius: 'var(--radius-control)',
              border: '1px solid var(--color-border)',
              fontSize: '12px',
              color: 'var(--color-secondary-text)',
              maxHeight: '100px',
              overflowY: 'auto',
            }}
          >
            <strong>Educational Security Notice v1.0:</strong>
            <p style={{ marginTop: '4px' }}>
              {noticeText || 'CipherVault encrypts all stored payloads across 14 independent cipher variants. Passwords are saved as salted Argon2id hashes. No password recovery is supported.'}
            </p>
          </div>

          <label
            style={{
              display: 'flex',
              alignItems: 'flex-start',
              gap: '10px',
              fontSize: '13px',
              color: 'var(--color-text)',
              cursor: 'pointer',
            }}
          >
            <input
              type="checkbox"
              required
              checked={noticeAck}
              onChange={(e) => setNoticeAck(e.target.checked)}
              style={{ marginTop: '2px' }}
            />
            <span>I acknowledge the CipherVault security notice v1.0 and understand that lost credentials cannot be recovered.</span>
          </label>

          <Button type="submit" disabled={submitting} style={{ marginTop: '8px', width: '100%' }}>
            {submitting ? 'Registering...' : 'Complete Registration'}
          </Button>
        </form>

        <div style={{ textAlign: 'center', marginTop: '24px', fontSize: '14px', color: 'var(--color-secondary-text)' }}>
          Already have an account?{' '}
          <button
            onClick={onSwitchToLogin}
            style={{ color: 'var(--color-primary)', fontWeight: 600 }}
          >
            Sign In
          </button>
        </div>
      </div>
    </div>
  );
};

