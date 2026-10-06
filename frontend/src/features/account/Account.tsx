import React, { useEffect, useState } from 'react';
import { api } from '../../api/client';
import type { Quota } from '../../api/types';
import { Button } from '../../components/Button';
import { Modal } from '../../components/Modal';
import { useAuth } from '../../context/AuthContext';

export const Account: React.FC = () => {
  const { user, refreshProfile, logout } = useAuth();
  const [quota, setQuota] = useState<Quota | null>(null);
  const [etag, setEtag] = useState<string>('');
  const [loading, setLoading] = useState(true);

  // Edit profile modal
  const [editModalOpen, setEditModalOpen] = useState(false);
  const [editFullName, setEditFullName] = useState('');
  const [editEmail, setEditEmail] = useState('');
  const [editBirthday, setEditBirthday] = useState('');
  const [editCurrentPassword, setEditCurrentPassword] = useState('');
  const [editError, setEditError] = useState<string | null>(null);

  // Change password modal
  const [passwordModalOpen, setPasswordModalOpen] = useState(false);
  const [currPassword, setCurrPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [passwordError, setPasswordError] = useState<string | null>(null);

  // Delete account modal
  const [deleteModalOpen, setDeleteModalOpen] = useState(false);
  const [deletePassword, setDeletePassword] = useState('');
  const [deleteError, setDeleteError] = useState<string | null>(null);

  useEffect(() => {
    loadAccountData();
  }, []);

  const loadAccountData = async () => {
    setLoading(true);
    try {
      const [{ profile, etag: currentEtag }, q] = await Promise.all([
        api.getMe(),
        api.getQuota(),
      ]);
      setEtag(currentEtag);
      setQuota(q);
      setEditFullName(profile.full_name);
      setEditEmail(profile.email);
      setEditBirthday(profile.birthday || '');
    } catch {
      // Ignore
    } finally {
      setLoading(false);
    }
  };

  const handleEditSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setEditError(null);
    try {
      const res = await api.patchMe(
        {
          full_name: editFullName,
          email: editEmail,
          birthday: editBirthday || null,
          current_password: editCurrentPassword,
        },
        etag
      );
      setEtag(res.etag);
      setEditModalOpen(false);
      setEditCurrentPassword('');
      await refreshProfile();
      await loadAccountData();
    } catch (err: any) {
      setEditError(err.message || 'Profile update failed');
    }
  };

  const handlePasswordSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (newPassword.length < 12) {
      setPasswordError('New password must be at least 12 characters.');
      return;
    }
    setPasswordError(null);
    try {
      await api.putPassword(currPassword, newPassword, etag);
      setPasswordModalOpen(false);
      setCurrPassword('');
      setNewPassword('');
      alert('Password updated successfully! Other sessions have been invalidated.');
      await loadAccountData();
    } catch (err: any) {
      setPasswordError(err.message || 'Password update failed');
    }
  };

  const handleDeleteSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setDeleteError(null);
    try {
      await api.deleteMe(deletePassword, etag);
      alert('Account and all associated encrypted files and replicas have been deleted.');
      await logout();
    } catch (err: any) {
      setDeleteError(err.message || 'Account deletion failed');
    }
  };

  const handleExportData = async () => {
    try {
      const profile = await api.exportMe();
      const blob = new Blob([JSON.stringify(profile, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'ciphervault_export_' + profile.username + '.json';
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
    } catch (err: any) {
      alert(err.message || 'Failed to export profile data');
    }
  };

  const formatBytes = (bytes: number) => {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  if (loading || !user) {
    return <div style={{ padding: '40px', textAlign: 'center' }}>Loading account profile...</div>;
  }

  const logicalPct = quota ? Math.min(100, (quota.logical_used_bytes / quota.logical_limit_bytes) * 100) : 0;
  const physicalPct = quota ? Math.min(100, (quota.physical_used_bytes / quota.physical_limit_bytes) * 100) : 0;
  const fileCountPct = quota ? Math.min(100, (quota.file_count / quota.file_count_limit) * 100) : 0;

  return (
    <div>
      <div style={{ marginBottom: '24px' }}>
        <h2 style={{ fontSize: '20px', fontWeight: 600, color: 'var(--color-text)' }}>Account & Storage Quota</h2>
        <p style={{ fontSize: '14px', color: 'var(--color-secondary-text)', marginTop: '4px' }}>
          Personal identity records and storage quotas. All profile fields are encrypted at rest across 14 independent variants.
        </p>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '24px', marginBottom: '32px' }}>
        {/* Profile Card */}
        <div
          style={{
            backgroundColor: 'var(--color-surface)',
            borderRadius: 'var(--radius-panel)',
            border: '1px solid var(--color-border)',
            padding: '24px',
          }}
        >
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
            <h3 style={{ fontSize: '16px', fontWeight: 600 }}>Personal Profile</h3>
            <Button size="sm" variant="secondary" onClick={() => setEditModalOpen(true)}>
              Edit Profile
            </Button>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
            <div>
              <div style={{ fontSize: '12px', color: 'var(--color-secondary-text)' }}>Full Name</div>
              <div style={{ fontSize: '15px', fontWeight: 500 }}>{user.full_name}</div>
            </div>
            <div>
              <div style={{ fontSize: '12px', color: 'var(--color-secondary-text)' }}>Username (Immutable)</div>
              <div style={{ fontSize: '15px', fontWeight: 500, fontFamily: 'var(--font-mono)' }}>@{user.username}</div>
            </div>
            <div>
              <div style={{ fontSize: '12px', color: 'var(--color-secondary-text)' }}>Email</div>
              <div style={{ fontSize: '15px', fontWeight: 500 }}>{user.email}</div>
            </div>
            <div>
              <div style={{ fontSize: '12px', color: 'var(--color-secondary-text)' }}>Birthday</div>
              <div style={{ fontSize: '15px', fontWeight: 500 }}>{user.birthday || 'Not provided'}</div>
            </div>
          </div>

          <div style={{ marginTop: '24px', paddingTop: '16px', borderTop: '1px solid var(--color-border)', display: 'flex', gap: '10px' }}>
            <Button size="sm" variant="secondary" onClick={() => setPasswordModalOpen(true)}>
              Change Password
            </Button>
            <Button size="sm" variant="secondary" onClick={handleExportData}>
              Export Data
            </Button>
          </div>
        </div>

        {/* Quota Usage Card */}
        <div
          style={{
            backgroundColor: 'var(--color-surface)',
            borderRadius: 'var(--radius-panel)',
            border: '1px solid var(--color-border)',
            padding: '24px',
          }}
        >
          <h3 style={{ fontSize: '16px', fontWeight: 600, marginBottom: '16px' }}>Storage Quota & Replicas</h3>

          {quota && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '13px', marginBottom: '6px' }}>
                  <span>Logical File Data</span>
                  <span style={{ fontWeight: 600 }}>
                    {formatBytes(quota.logical_used_bytes)} / {formatBytes(quota.logical_limit_bytes)} ({logicalPct.toFixed(1)}%)
                  </span>
                </div>
                <div style={{ height: '8px', backgroundColor: '#E2E8F0', borderRadius: '4px', overflow: 'hidden' }}>
                  <div style={{ height: '100%', width: logicalPct + '%', backgroundColor: 'var(--color-primary)' }} />
                </div>
              </div>

              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '13px', marginBottom: '6px' }}>
                  <span>Physical Storage (14 Replicas + Framing)</span>
                  <span style={{ fontWeight: 600 }}>
                    {formatBytes(quota.physical_used_bytes)} / {formatBytes(quota.physical_limit_bytes)} ({physicalPct.toFixed(1)}%)
                  </span>
                </div>
                <div style={{ height: '8px', backgroundColor: '#E2E8F0', borderRadius: '4px', overflow: 'hidden' }}>
                  <div style={{ height: '100%', width: physicalPct + '%', backgroundColor: '#8B5CF6' }} />
                </div>
              </div>

              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '13px', marginBottom: '6px' }}>
                  <span>File Count</span>
                  <span style={{ fontWeight: 600 }}>
                    {quota.file_count} / {quota.file_count_limit} files ({fileCountPct.toFixed(1)}%)
                  </span>
                </div>
                <div style={{ height: '8px', backgroundColor: '#E2E8F0', borderRadius: '4px', overflow: 'hidden' }}>
                  <div style={{ height: '100%', width: fileCountPct + '%', backgroundColor: '#10B981' }} />
                </div>
              </div>

              <div style={{ marginTop: '8px', padding: '10px 12px', backgroundColor: '#F8FAFC', borderRadius: '8px', border: '1px solid var(--color-border)', fontSize: '12px', color: 'var(--color-secondary-text)' }}>
                ℹ️ Every uploaded file automatically provisions 14 independent cryptographic copies with unique random salts, IVs, and HMAC-SHA256 integrity tags.
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Danger Zone */}
      <div
        style={{
          backgroundColor: '#FEF2F2',
          borderRadius: 'var(--radius-panel)',
          border: '1px solid #FECACA',
          padding: '24px',
        }}
      >
        <h3 style={{ fontSize: '16px', fontWeight: 600, color: 'var(--color-danger)', marginBottom: '8px' }}>
          Danger Zone
        </h3>
        <p style={{ fontSize: '13px', color: '#991B1B', marginBottom: '16px' }}>
          Permanently delete your account. This operation irrevocably deletes your user profile, all 14 encrypted copies of each owned file, and all associated recipient grants.
        </p>
        <Button variant="danger" size="sm" onClick={() => setDeleteModalOpen(true)}>
          Permanently Delete Account
        </Button>
      </div>

      {/* Edit Profile Modal */}
      <Modal isOpen={editModalOpen} onClose={() => setEditModalOpen(false)} title="Edit Profile">
        <form onSubmit={handleEditSubmit}>
          {editError && (
            <div style={{ padding: '10px', backgroundColor: '#FEF2F2', border: '1px solid #FECACA', borderRadius: '6px', color: 'var(--color-danger)', fontSize: '13px', marginBottom: '14px' }}>
              {editError}
            </div>
          )}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '14px', marginBottom: '20px' }}>
            <div>
              <label style={{ display: 'block', fontSize: '13px', fontWeight: 500, marginBottom: '4px' }}>Full Name</label>
              <input
                type="text"
                required
                value={editFullName}
                onChange={(e) => setEditFullName(e.target.value)}
                style={{ width: '100%', height: '38px', padding: '0 10px', borderRadius: '6px', border: '1px solid var(--color-border)' }}
              />
            </div>
            <div>
              <label style={{ display: 'block', fontSize: '13px', fontWeight: 500, marginBottom: '4px' }}>Email</label>
              <input
                type="email"
                required
                value={editEmail}
                onChange={(e) => setEditEmail(e.target.value)}
                style={{ width: '100%', height: '38px', padding: '0 10px', borderRadius: '6px', border: '1px solid var(--color-border)' }}
              />
            </div>
            <div>
              <label style={{ display: 'block', fontSize: '13px', fontWeight: 500, marginBottom: '4px' }}>Birthday</label>
              <input
                type="date"
                value={editBirthday}
                onChange={(e) => setEditBirthday(e.target.value)}
                style={{ width: '100%', height: '38px', padding: '0 10px', borderRadius: '6px', border: '1px solid var(--color-border)' }}
              />
            </div>
            <div>
              <label style={{ display: 'block', fontSize: '13px', fontWeight: 500, marginBottom: '4px' }}>Confirm Current Password</label>
              <input
                type="password"
                required
                value={editCurrentPassword}
                onChange={(e) => setEditCurrentPassword(e.target.value)}
                placeholder="Required to authorize changes"
                style={{ width: '100%', height: '38px', padding: '0 10px', borderRadius: '6px', border: '1px solid var(--color-border)' }}
              />
            </div>
          </div>
          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '10px' }}>
            <Button type="button" variant="secondary" onClick={() => setEditModalOpen(false)}>Cancel</Button>
            <Button type="submit" variant="primary">Save Changes</Button>
          </div>
        </form>
      </Modal>

      {/* Change Password Modal */}
      <Modal isOpen={passwordModalOpen} onClose={() => setPasswordModalOpen(false)} title="Change Password">
        <form onSubmit={handlePasswordSubmit}>
          {passwordError && (
            <div style={{ padding: '10px', backgroundColor: '#FEF2F2', border: '1px solid #FECACA', borderRadius: '6px', color: 'var(--color-danger)', fontSize: '13px', marginBottom: '14px' }}>
              {passwordError}
            </div>
          )}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '14px', marginBottom: '20px' }}>
            <div>
              <label style={{ display: 'block', fontSize: '13px', fontWeight: 500, marginBottom: '4px' }}>Current Password</label>
              <input
                type="password"
                required
                value={currPassword}
                onChange={(e) => setCurrPassword(e.target.value)}
                style={{ width: '100%', height: '38px', padding: '0 10px', borderRadius: '6px', border: '1px solid var(--color-border)' }}
              />
            </div>
            <div>
              <label style={{ display: 'block', fontSize: '13px', fontWeight: 500, marginBottom: '4px' }}>New Password (≥ 12 characters)</label>
              <input
                type="password"
                required
                minLength={12}
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
                style={{ width: '100%', height: '38px', padding: '0 10px', borderRadius: '6px', border: '1px solid var(--color-border)' }}
              />
            </div>
          </div>
          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '10px' }}>
            <Button type="button" variant="secondary" onClick={() => setPasswordModalOpen(false)}>Cancel</Button>
            <Button type="submit" variant="primary">Update Password</Button>
          </div>
        </form>
      </Modal>

      {/* Delete Account Modal */}
      <Modal isOpen={deleteModalOpen} onClose={() => setDeleteModalOpen(false)} title="Confirm Account Deletion">
        <form onSubmit={handleDeleteSubmit}>
          {deleteError && (
            <div style={{ padding: '10px', backgroundColor: '#FEF2F2', border: '1px solid #FECACA', borderRadius: '6px', color: 'var(--color-danger)', fontSize: '13px', marginBottom: '14px' }}>
              {deleteError}
            </div>
          )}
          <p style={{ fontSize: '14px', color: 'var(--color-danger)', marginBottom: '14px', fontWeight: 500 }}>
            This action is irreversible. All your private files and encrypted variants will be immediately erased.
          </p>
          <div style={{ marginBottom: '20px' }}>
            <label style={{ display: 'block', fontSize: '13px', fontWeight: 500, marginBottom: '4px' }}>Confirm Password</label>
            <input
              type="password"
              required
              value={deletePassword}
              onChange={(e) => setDeletePassword(e.target.value)}
              placeholder="Enter your password to confirm"
              style={{ width: '100%', height: '38px', padding: '0 10px', borderRadius: '6px', border: '1px solid var(--color-border)' }}
            />
          </div>
          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '10px' }}>
            <Button type="button" variant="secondary" onClick={() => setDeleteModalOpen(false)}>Cancel</Button>
            <Button type="submit" variant="danger">Permanently Delete</Button>
          </div>
        </form>
      </Modal>
    </div>
  );
};

