import React, { useEffect, useState } from 'react';
import { api } from '../../api/client';
import type { Grant, OwnerFile } from '../../api/types';
import { Badge } from '../../components/Badge';
import { Button } from '../../components/Button';
import { FileIcon } from '../../components/FileIcon';
import { Modal } from '../../components/Modal';

export const MyFiles: React.FC = () => {
  const [files, setFiles] = useState<OwnerFile[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Upload state
  const [uploadFile, setUploadFile] = useState<File | null>(null);
  const [uploadCategory, setUploadCategory] = useState<string>('');
  const [uploading, setUploading] = useState(false);
  const [uploadStatus, setUploadStatus] = useState<string | null>(null);

  // Modal states
  const [activeFile, setActiveFile] = useState<OwnerFile | null>(null);
  const [etag, setEtag] = useState<string>('');

  // Download modal
  const [downloadModalOpen, setDownloadModalOpen] = useState(false);
  const [selectedVariant, setSelectedVariant] = useState('aes-256-ctr');
  const [downloading, setDownloading] = useState(false);

  // Rename modal
  const [renameModalOpen, setRenameModalOpen] = useState(false);
  const [newFilename, setNewFilename] = useState('');

  // Replace modal
  const [replaceModalOpen, setReplaceModalOpen] = useState(false);
  const [replaceFile, setReplaceFile] = useState<File | null>(null);

  // Delete modal
  const [deleteModalOpen, setDeleteModalOpen] = useState(false);

  // Grants modal
  const [grantsModalOpen, setGrantsModalOpen] = useState(false);
  const [grants, setGrants] = useState<Grant[]>([]);
  const [recipientUsername, setRecipientUsername] = useState('');
  const [grantType, setGrantType] = useState<'metadata' | 'download'>('metadata');
  const [grantLoading, setGrantLoading] = useState(false);

  useEffect(() => {
    loadFiles();
  }, []);

  const loadFiles = async () => {
    setLoading(true);
    setError(null);
    try {
      const page = await api.getMine(0, 100);
      setFiles(page.items);
    } catch (err: any) {
      setError(err.message || 'Failed to load your files');
    } finally {
      setLoading(false);
    }
  };

  const handleUploadSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!uploadFile) return;

    setUploading(true);
    setUploadStatus('Generating 14 independent cryptographic variants...');
    setError(null);

    const formData = new FormData();
    formData.append('file', uploadFile);
    if (uploadCategory) {
      formData.append('category', uploadCategory);
    }

    try {
      await api.uploadFile(formData);
      setUploadFile(null);
      setUploadCategory('');
      setUploadStatus(null);
      await loadFiles();
    } catch (err: any) {
      setError(err.message || 'Upload failed');
      setUploadStatus(null);
    } finally {
      setUploading(false);
    }
  };

  const openDownload = (f: OwnerFile) => {
    setActiveFile(f);
    setSelectedVariant('aes-256-ctr');
    setDownloadModalOpen(true);
  };

  const handleDownloadConfirm = async () => {
    if (!activeFile) return;
    setDownloading(true);
    try {
      await api.downloadFile(activeFile.id, activeFile.filename, selectedVariant);
      setDownloadModalOpen(false);
    } catch (err: any) {
      alert(err.message || 'Download failed');
    } finally {
      setDownloading(false);
    }
  };

  const openRename = async (f: OwnerFile) => {
    try {
      const { etag: currentEtag } = await api.getFile(f.id);
      setActiveFile(f);
      setNewFilename(f.filename);
      setEtag(currentEtag);
      setRenameModalOpen(true);
    } catch (err: any) {
      alert(err.message || 'Failed to prepare file rename');
    }
  };

  const handleRenameConfirm = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!activeFile) return;
    try {
      await api.renameFile(activeFile.id, newFilename, etag);
      setRenameModalOpen(false);
      await loadFiles();
    } catch (err: any) {
      alert(err.message || 'Rename failed');
    }
  };

  const openReplace = async (f: OwnerFile) => {
    try {
      const { etag: currentEtag } = await api.getFile(f.id);
      setActiveFile(f);
      setReplaceFile(null);
      setEtag(currentEtag);
      setReplaceModalOpen(true);
    } catch (err: any) {
      alert(err.message || 'Failed to prepare file replacement');
    }
  };

  const handleReplaceConfirm = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!activeFile || !replaceFile) return;
    const formData = new FormData();
    formData.append('file', replaceFile);
    try {
      await api.replaceFile(activeFile.id, formData, etag);
      setReplaceModalOpen(false);
      await loadFiles();
    } catch (err: any) {
      alert(err.message || 'Replacement failed');
    }
  };

  const openDelete = async (f: OwnerFile) => {
    try {
      const { etag: currentEtag } = await api.getFile(f.id);
      setActiveFile(f);
      setEtag(currentEtag);
      setDeleteModalOpen(true);
    } catch (err: any) {
      alert(err.message || 'Failed to prepare deletion');
    }
  };

  const handleDeleteConfirm = async () => {
    if (!activeFile) return;
    try {
      await api.deleteFile(activeFile.id, etag);
      setDeleteModalOpen(false);
      await loadFiles();
    } catch (err: any) {
      alert(err.message || 'Delete failed');
    }
  };

  const handleToggleListing = async (f: OwnerFile) => {
    try {
      const { etag: currentEtag } = await api.getFile(f.id);
      await api.setListing(f.id, !f.listed, currentEtag);
      await loadFiles();
    } catch (err: any) {
      alert(err.message || 'Failed to toggle listing');
    }
  };

  const openGrants = async (f: OwnerFile) => {
    try {
      const { etag: currentEtag } = await api.getFile(f.id);
      setActiveFile(f);
      setEtag(currentEtag);
      setRecipientUsername('');
      setGrantType('metadata');
      const currentGrants = await api.getGrants(f.id);
      setGrants(currentGrants);
      setGrantsModalOpen(true);
    } catch (err: any) {
      alert(err.message || 'Failed to load grants');
    }
  };

  const handleAddGrant = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!activeFile || !recipientUsername) return;
    setGrantLoading(true);
    try {
      const res = await api.putGrant(
        activeFile.id,
        recipientUsername,
        {
          view_metadata: true,
          download: grantType === 'download',
        },
        etag
      );
      setEtag(res.etag);
      const updatedGrants = await api.getGrants(activeFile.id);
      setGrants(updatedGrants);
      setRecipientUsername('');
    } catch (err: any) {
      alert(err.message || 'Failed to add grant');
    } finally {
      setGrantLoading(false);
    }
  };

  const handleRevokeGrant = async (username: string) => {
    if (!activeFile) return;
    try {
      const res = await api.deleteGrant(activeFile.id, username, etag);
      setEtag(res.etag);
      const updatedGrants = await api.getGrants(activeFile.id);
      setGrants(updatedGrants);
    } catch (err: any) {
      alert(err.message || 'Failed to revoke grant');
    }
  };

  const formatBytes = (bytes: number) => {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  return (
    <div>
      {/* Upload Dropzone / Panel */}
      <div
        style={{
          backgroundColor: 'var(--color-surface)',
          borderRadius: 'var(--radius-panel)',
          border: '1px solid var(--color-border)',
          padding: '20px 24px',
          marginBottom: '24px',
        }}
      >
        <h3 style={{ fontSize: '16px', fontWeight: 600, marginBottom: '12px' }}>Upload File to Encrypted Vault</h3>
        <form onSubmit={handleUploadSubmit} style={{ display: 'flex', flexWrap: 'wrap', gap: '16px', alignItems: 'flex-end' }}>
          <div style={{ flex: 1, minWidth: '240px' }}>
            <label style={{ display: 'block', fontSize: '13px', fontWeight: 500, marginBottom: '6px' }}>
              Choose File <span style={{ color: 'var(--color-secondary-text)' }}>(Images, PDF, Office, Videos)</span>
            </label>
            <input
              type="file"
              required
              onChange={(e) => setUploadFile(e.target.files?.[0] || null)}
              style={{
                width: '100%',
                padding: '8px',
                border: '1px solid var(--color-border)',
                borderRadius: 'var(--radius-control)',
                backgroundColor: '#F8FAFC',
              }}
            />
          </div>

          <div style={{ width: '180px' }}>
            <label style={{ display: 'block', fontSize: '13px', fontWeight: 500, marginBottom: '6px' }}>
              Category
            </label>
            <select
              value={uploadCategory}
              onChange={(e) => setUploadCategory(e.target.value)}
              style={{
                width: '100%',
                height: 'var(--input-height)',
                padding: '0 10px',
                border: '1px solid var(--color-border)',
                borderRadius: 'var(--radius-control)',
                backgroundColor: 'var(--color-surface)',
              }}
            >
              <option value="">Auto-detect</option>
              <option value="id_card">ID-card Image</option>
              <option value="image">Image</option>
              <option value="document">Document</option>
              <option value="video">Video</option>
            </select>
          </div>

          <Button type="submit" disabled={!uploadFile || uploading} style={{ minWidth: '140px' }}>
            {uploading ? 'Sealing...' : 'Upload & Seal'}
          </Button>
        </form>

        {uploadStatus && (
          <div style={{ marginTop: '12px', fontSize: '13px', color: 'var(--color-primary)', fontWeight: 500 }}>
            ⏳ {uploadStatus}
          </div>
        )}
      </div>

      {error && (
        <div style={{ padding: '12px', backgroundColor: '#FEF2F2', border: '1px solid #FECACA', borderRadius: '8px', color: 'var(--color-danger)', marginBottom: '16px' }}>
          {error}
        </div>
      )}

      {/* Files Table */}
      {loading ? (
        <div style={{ padding: '40px', textAlign: 'center', color: 'var(--color-secondary-text)' }}>
          Loading your encrypted files...
        </div>
      ) : files.length === 0 ? (
        <div
          style={{
            padding: '48px',
            textAlign: 'center',
            backgroundColor: 'var(--color-surface)',
            borderRadius: 'var(--radius-panel)',
            border: '1px solid var(--color-border)',
          }}
        >
          <div style={{ fontSize: '32px', marginBottom: '8px' }}>📦</div>
          <p style={{ fontWeight: 600, color: 'var(--color-text)' }}>Your vault is empty</p>
          <p style={{ fontSize: '13px', color: 'var(--color-secondary-text)', marginTop: '4px' }}>
            Upload a document, mock ID, image, or video above to create 14 encrypted copies.
          </p>
        </div>
      ) : (
        <div
          style={{
            backgroundColor: 'var(--color-surface)',
            borderRadius: 'var(--radius-panel)',
            border: '1px solid var(--color-border)',
            overflow: 'hidden',
          }}
        >
          <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left' }}>
            <thead>
              <tr style={{ backgroundColor: '#F8FAFC', borderBottom: '1px solid var(--color-border)', fontSize: '13px', color: 'var(--color-secondary-text)' }}>
                <th style={{ padding: '12px 16px' }}>Filename</th>
                <th style={{ padding: '12px 16px' }}>Size</th>
                <th style={{ padding: '12px 16px' }}>Revision</th>
                <th style={{ padding: '12px 16px' }}>Catalog Status</th>
                <th style={{ padding: '12px 16px', textAlign: 'right' }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {files.map((f) => (
                <tr key={f.id} style={{ borderBottom: '1px solid #F1F5F9' }}>
                  <td style={{ padding: '14px 16px' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                      <FileIcon filename={f.filename} />
                      <div>
                        <div style={{ fontWeight: 500, color: 'var(--color-text)' }}>{f.filename}</div>
                        <div style={{ fontSize: '12px', color: 'var(--color-secondary-text)' }}>{f.mime}</div>
                      </div>
                    </div>
                  </td>
                  <td style={{ padding: '14px 16px', fontSize: '14px', color: 'var(--color-secondary-text)' }}>
                    {formatBytes(f.size_bytes)}
                  </td>
                  <td style={{ padding: '14px 16px', fontSize: '13px', color: 'var(--color-secondary-text)' }}>
                    v{f.content_revision} (r{f.revision})
                  </td>
                  <td style={{ padding: '14px 16px' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                      <Badge type={f.listed ? 'listed' : 'private'} />
                      <button
                        onClick={() => handleToggleListing(f)}
                        style={{ fontSize: '12px', color: 'var(--color-primary)', textDecoration: 'underline' }}
                      >
                        {f.listed ? 'Unlist' : 'List in Catalog'}
                      </button>
                    </div>
                  </td>
                  <td style={{ padding: '14px 16px', textAlign: 'right' }}>
                    <div style={{ display: 'inline-flex', gap: '6px' }}>
                      <Button size="sm" variant="primary" onClick={() => openDownload(f)}>
                        Download
                      </Button>
                      <Button size="sm" variant="secondary" onClick={() => openGrants(f)}>
                        Share
                      </Button>
                      <Button size="sm" variant="secondary" onClick={() => openRename(f)}>
                        Rename
                      </Button>
                      <Button size="sm" variant="secondary" onClick={() => openReplace(f)}>
                        Replace
                      </Button>
                      <Button size="sm" variant="danger" onClick={() => openDelete(f)}>
                        Delete
                      </Button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Download Multi-Variant Modal */}
      <Modal isOpen={downloadModalOpen} onClose={() => setDownloadModalOpen(false)} title="Download Decrypted Variant">
        {activeFile && (
          <div>
            <p style={{ fontSize: '14px', marginBottom: '16px' }}>
              Select which of the 14 independently stored cipher variants to authenticate and decrypt for <strong>{activeFile.filename}</strong>:
            </p>
            <div style={{ marginBottom: '20px' }}>
              <label style={{ display: 'block', fontSize: '13px', fontWeight: 500, marginBottom: '6px' }}>
                Cryptographic Variant
              </label>
              <select
                value={selectedVariant}
                onChange={(e) => setSelectedVariant(e.target.value)}
                style={{
                  width: '100%',
                  height: 'var(--input-height)',
                  padding: '0 12px',
                  borderRadius: 'var(--radius-control)',
                  border: '1px solid var(--color-border)',
                  fontFamily: 'var(--font-mono)',
                  fontSize: '14px',
                }}
              >
                {activeFile.variants.map((v) => (
                  <option key={v} value={v}>
                    {v} {v === 'aes-256-ctr' ? '(Default • Recommended)' : ''}
                  </option>
                ))}
              </select>
            </div>
            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '10px' }}>
              <Button variant="secondary" onClick={() => setDownloadModalOpen(false)}>
                Cancel
              </Button>
              <Button variant="primary" disabled={downloading} onClick={handleDownloadConfirm}>
                {downloading ? 'Decrypting...' : 'Authenticate & Download'}
              </Button>
            </div>
          </div>
        )}
      </Modal>

      {/* Rename Modal */}
      <Modal isOpen={renameModalOpen} onClose={() => setRenameModalOpen(false)} title="Rename File">
        <form onSubmit={handleRenameConfirm}>
          <p style={{ fontSize: '14px', marginBottom: '16px', color: 'var(--color-secondary-text)' }}>
            You may change the display name. The extension must be preserved to prevent format spoofing.
          </p>
          <div style={{ marginBottom: '20px' }}>
            <label style={{ display: 'block', fontSize: '13px', fontWeight: 500, marginBottom: '6px' }}>
              New Filename
            </label>
            <input
              type="text"
              required
              value={newFilename}
              onChange={(e) => setNewFilename(e.target.value)}
              style={{
                width: '100%',
                height: 'var(--input-height)',
                padding: '0 12px',
                borderRadius: 'var(--radius-control)',
                border: '1px solid var(--color-border)',
              }}
            />
          </div>
          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '10px' }}>
            <Button type="button" variant="secondary" onClick={() => setRenameModalOpen(false)}>
              Cancel
            </Button>
            <Button type="submit" variant="primary">
              Save New Name
            </Button>
          </div>
        </form>
      </Modal>

      {/* Replace Content Modal */}
      <Modal isOpen={replaceModalOpen} onClose={() => setReplaceModalOpen(false)} title="Replace File Content">
        <form onSubmit={handleReplaceConfirm}>
          <div style={{ padding: '12px', backgroundColor: '#FEF3C7', border: '1px solid #FDE68A', borderRadius: '8px', color: '#92400E', fontSize: '13px', marginBottom: '16px' }}>
            ⚠️ <strong>Security Notice:</strong> Replacing file content creates a brand new revision. In accordance with zero-overexposure policy, all existing recipient grants will be revoked and public catalog listing will be reset to private.
          </div>
          <div style={{ marginBottom: '20px' }}>
            <label style={{ display: 'block', fontSize: '13px', fontWeight: 500, marginBottom: '6px' }}>
              Select Replacement File
            </label>
            <input
              type="file"
              required
              onChange={(e) => setReplaceFile(e.target.files?.[0] || null)}
              style={{ width: '100%', padding: '8px', border: '1px solid var(--color-border)', borderRadius: 'var(--radius-control)' }}
            />
          </div>
          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '10px' }}>
            <Button type="button" variant="secondary" onClick={() => setReplaceModalOpen(false)}>
              Cancel
            </Button>
            <Button type="submit" variant="danger" disabled={!replaceFile}>
              Replace & Reset Grants
            </Button>
          </div>
        </form>
      </Modal>

      {/* Delete Confirmation Modal */}
      <Modal isOpen={deleteModalOpen} onClose={() => setDeleteModalOpen(false)} title="Delete File Permanently">
        <div>
          <p style={{ fontSize: '14px', marginBottom: '16px' }}>
            Are you sure you want to delete <strong>{activeFile?.filename}</strong>? All 14 encrypted copies and recipient access grants will be permanently purged from SQLite.
          </p>
          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '10px' }}>
            <Button variant="secondary" onClick={() => setDeleteModalOpen(false)}>
              Cancel
            </Button>
            <Button variant="danger" onClick={handleDeleteConfirm}>
              Permanently Delete
            </Button>
          </div>
        </div>
      </Modal>

      {/* Manage Grants Modal */}
      <Modal isOpen={grantsModalOpen} onClose={() => setGrantsModalOpen(false)} title="Manage Recipient Grants" maxWidth="600px">
        <div>
          <form onSubmit={handleAddGrant} style={{ marginBottom: '24px', paddingBottom: '20px', borderBottom: '1px solid var(--color-border)' }}>
            <h4 style={{ fontSize: '14px', fontWeight: 600, marginBottom: '10px' }}>Grant Access to Registered User</h4>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px', marginBottom: '12px' }}>
              <div>
                <label style={{ display: 'block', fontSize: '12px', fontWeight: 500, marginBottom: '4px' }}>
                  Exact Username
                </label>
                <input
                  type="text"
                  required
                  placeholder="e.g. bob"
                  value={recipientUsername}
                  onChange={(e) => setRecipientUsername(e.target.value)}
                  style={{
                    width: '100%',
                    height: '38px',
                    padding: '0 10px',
                    borderRadius: 'var(--radius-control)',
                    border: '1px solid var(--color-border)',
                  }}
                />
              </div>
              <div>
                <label style={{ display: 'block', fontSize: '12px', fontWeight: 500, marginBottom: '4px' }}>
                  Permission Level
                </label>
                <select
                  value={grantType}
                  onChange={(e) => setGrantType(e.target.value as any)}
                  style={{
                    width: '100%',
                    height: '38px',
                    padding: '0 10px',
                    borderRadius: 'var(--radius-control)',
                    border: '1px solid var(--color-border)',
                  }}
                >
                  <option value="metadata">Metadata Discovery Only</option>
                  <option value="download">Metadata + Full Download</option>
                </select>
              </div>
            </div>
            <Button type="submit" size="sm" disabled={grantLoading || !recipientUsername}>
              {grantLoading ? 'Granting...' : 'Add Grant'}
            </Button>
          </form>

          <div>
            <h4 style={{ fontSize: '14px', fontWeight: 600, marginBottom: '10px' }}>Active Access Grants</h4>
            {grants.length === 0 ? (
              <p style={{ fontSize: '13px', color: 'var(--color-secondary-text)' }}>
                No users have been granted access to this file yet.
              </p>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                {grants.map((g) => (
                  <div
                    key={g.recipient_username}
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'space-between',
                      padding: '10px 14px',
                      backgroundColor: '#F8FAFC',
                      borderRadius: 'var(--radius-control)',
                      border: '1px solid var(--color-border)',
                    }}
                  >
                    <div>
                      <span style={{ fontWeight: 600, fontSize: '14px' }}>@{g.recipient_username}</span>
                      <div style={{ marginTop: '2px' }}>
                        <Badge type={g.download ? 'download' : 'metadata'} />
                      </div>
                    </div>
                    <Button size="sm" variant="danger" onClick={() => handleRevokeGrant(g.recipient_username)}>
                      Revoke
                    </Button>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </Modal>
    </div>
  );
};

