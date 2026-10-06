import React, { useEffect, useState } from 'react';
import { api } from '../../api/client';
import type { DownloadFile, FileDetail } from '../../api/types';
import { isDownloadFile } from '../../api/types';
import { Badge } from '../../components/Badge';
import { Button } from '../../components/Button';
import { FileIcon } from '../../components/FileIcon';
import { Modal } from '../../components/Modal';

export const SharedFiles: React.FC = () => {
  const [files, setFiles] = useState<FileDetail[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [activeDownloadFile, setActiveDownloadFile] = useState<DownloadFile | null>(null);
  const [downloadModalOpen, setDownloadModalOpen] = useState(false);
  const [selectedVariant, setSelectedVariant] = useState('aes-256-ctr');
  const [downloading, setDownloading] = useState(false);

  useEffect(() => {
    loadSharedFiles();
  }, []);

  const loadSharedFiles = async () => {
    setLoading(true);
    setError(null);
    try {
      const page = await api.getShared(0, 100);
      setFiles(page.items);
    } catch (err: any) {
      setError(err.message || 'Failed to load shared files');
    } finally {
      setLoading(false);
    }
  };

  const openDownload = (f: DownloadFile) => {
    setActiveDownloadFile(f);
    setSelectedVariant('aes-256-ctr');
    setDownloadModalOpen(true);
  };

  const handleDownloadConfirm = async () => {
    if (!activeDownloadFile) return;
    setDownloading(true);
    try {
      await api.downloadFile(activeDownloadFile.id, activeDownloadFile.filename, selectedVariant);
      setDownloadModalOpen(false);
    } catch (err: any) {
      alert(err.message || 'Download failed');
    } finally {
      setDownloading(false);
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
      <div style={{ marginBottom: '24px' }}>
        <h2 style={{ fontSize: '20px', fontWeight: 600, color: 'var(--color-text)' }}>Files Shared With You</h2>
        <p style={{ fontSize: '14px', color: 'var(--color-secondary-text)', marginTop: '4px' }}>
          Files where an owner has explicitly granted you metadata discovery or full download access.
        </p>
      </div>

      {error && (
        <div style={{ padding: '12px', backgroundColor: '#FEF2F2', border: '1px solid #FECACA', borderRadius: '8px', color: 'var(--color-danger)', marginBottom: '16px' }}>
          {error}
        </div>
      )}

      {loading ? (
        <div style={{ padding: '40px', textAlign: 'center', color: 'var(--color-secondary-text)' }}>
          Loading shared files...
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
          <div style={{ fontSize: '32px', marginBottom: '8px' }}>🤝</div>
          <p style={{ fontWeight: 600, color: 'var(--color-text)' }}>No files shared with you yet</p>
          <p style={{ fontSize: '13px', color: 'var(--color-secondary-text)', marginTop: '4px' }}>
            When another registered user shares a file with your exact username, it will appear here.
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
                <th style={{ padding: '12px 16px' }}>Owner</th>
                <th style={{ padding: '12px 16px' }}>Access Level</th>
                <th style={{ padding: '12px 16px' }}>Size</th>
                <th style={{ padding: '12px 16px', textAlign: 'right' }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {files.map((f) => {
                const canDl = isDownloadFile(f);
                return (
                  <tr key={f.id} style={{ borderBottom: '1px solid #F1F5F9' }}>
                    <td style={{ padding: '14px 16px' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                        <FileIcon filename={f.filename} />
                        <div>
                          <div style={{ fontWeight: 500, color: 'var(--color-text)' }}>{f.filename}</div>
                          {canDl && <div style={{ fontSize: '12px', color: 'var(--color-secondary-text)' }}>{f.mime}</div>}
                        </div>
                      </div>
                    </td>
                    <td style={{ padding: '14px 16px', fontSize: '14px', color: 'var(--color-secondary-text)' }}>
                      @{f.owner_username}
                    </td>
                    <td style={{ padding: '14px 16px' }}>
                      <Badge type={canDl ? 'download' : 'metadata'} />
                    </td>
                    <td style={{ padding: '14px 16px', fontSize: '13px', color: 'var(--color-secondary-text)' }}>
                      {canDl ? formatBytes(f.size_bytes) : '—'}
                    </td>
                    <td style={{ padding: '14px 16px', textAlign: 'right' }}>
                      {canDl ? (
                        <Button size="sm" variant="primary" onClick={() => openDownload(f)}>
                          Download
                        </Button>
                      ) : (
                        <span style={{ fontSize: '12px', color: 'var(--color-secondary-text)' }}>
                          No Download Permission
                        </span>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      {/* Multi-variant download modal */}
      <Modal isOpen={downloadModalOpen} onClose={() => setDownloadModalOpen(false)} title="Download Decrypted Variant">
        {activeDownloadFile && (
          <div>
            <p style={{ fontSize: '14px', marginBottom: '16px' }}>
              Select which cryptographic variant to authenticate and decrypt for <strong>{activeDownloadFile.filename}</strong>:
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
                {activeDownloadFile.variants.map((v) => (
                  <option key={v} value={v}>
                    {v} {v === 'aes-256-ctr' ? '(Default)' : ''}
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
    </div>
  );
};

