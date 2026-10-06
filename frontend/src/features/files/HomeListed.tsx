import React, { useEffect, useState } from 'react';
import { api } from '../../api/client';
import type { Metadata } from '../../api/types';
import { Badge } from '../../components/Badge';
import { FileIcon } from '../../components/FileIcon';

export const HomeListed: React.FC = () => {
  const [files, setFiles] = useState<Metadata[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    loadListedFiles();
  }, []);

  const loadListedFiles = async () => {
    setLoading(true);
    setError(null);
    try {
      const page = await api.getListed(0, 100);
      setFiles(page.items);
    } catch (err: any) {
      setError(err.message || 'Failed to load public catalog');
    } finally {
      setLoading(false);
    }
  };

  const filtered = files.filter((f) =>
    f.filename.toLowerCase().includes(search.toLowerCase()) ||
    f.owner_username.toLowerCase().includes(search.toLowerCase())
  );

  return (
    <div>
      <div style={{ marginBottom: '24px' }}>
        <h2 style={{ fontSize: '20px', fontWeight: 600, color: 'var(--color-text)' }}>Public Listed Files</h2>
        <p style={{ fontSize: '14px', color: 'var(--color-secondary-text)', marginTop: '4px' }}>
          Discoverable files opted-in by their owners. In accordance with zero-leakage security, listing grants metadata discovery only. Plaintext downloads require an explicit grant.
        </p>
      </div>

      <div style={{ display: 'flex', gap: '16px', marginBottom: '20px' }}>
        <input
          type="text"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder="Search by filename or owner username..."
          style={{
            flex: 1,
            maxWidth: '400px',
            height: '40px',
            padding: '0 12px',
            borderRadius: 'var(--radius-control)',
            border: '1px solid var(--color-border)',
            outline: 'none',
          }}
        />
        <button
          onClick={loadListedFiles}
          style={{
            padding: '0 16px',
            backgroundColor: 'var(--color-surface)',
            border: '1px solid var(--color-border)',
            borderRadius: 'var(--radius-control)',
            fontSize: '14px',
            fontWeight: 500,
          }}
        >
          Refresh
        </button>
      </div>

      {error && (
        <div style={{ padding: '12px', backgroundColor: '#FEF2F2', border: '1px solid #FECACA', borderRadius: '8px', color: 'var(--color-danger)', marginBottom: '16px' }}>
          {error}
        </div>
      )}

      {loading ? (
        <div style={{ padding: '40px', textAlign: 'center', color: 'var(--color-secondary-text)' }}>
          Loading public catalog...
        </div>
      ) : filtered.length === 0 ? (
        <div
          style={{
            padding: '48px',
            textAlign: 'center',
            backgroundColor: 'var(--color-surface)',
            borderRadius: 'var(--radius-panel)',
            border: '1px solid var(--color-border)',
          }}
        >
          <div style={{ fontSize: '32px', marginBottom: '8px' }}>📂</div>
          <p style={{ fontWeight: 600, color: 'var(--color-text)' }}>No files listed publicly yet</p>
          <p style={{ fontSize: '13px', color: 'var(--color-secondary-text)', marginTop: '4px' }}>
            Files remain strictly private by default until the owner explicitly opts them into the catalog.
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
                <th style={{ padding: '12px 16px' }}>File</th>
                <th style={{ padding: '12px 16px' }}>Owner</th>
                <th style={{ padding: '12px 16px' }}>Visibility</th>
                <th style={{ padding: '12px 16px' }}>Access Rule</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((f) => (
                <tr key={f.id} style={{ borderBottom: '1px solid #F1F5F9' }}>
                  <td style={{ padding: '14px 16px' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                      <FileIcon filename={f.filename} />
                      <span style={{ fontWeight: 500, color: 'var(--color-text)' }}>{f.filename}</span>
                    </div>
                  </td>
                  <td style={{ padding: '14px 16px', fontSize: '14px', color: 'var(--color-secondary-text)' }}>
                    @{f.owner_username}
                  </td>
                  <td style={{ padding: '14px 16px' }}>
                    <Badge type="listed" />
                  </td>
                  <td style={{ padding: '14px 16px', fontSize: '13px', color: 'var(--color-secondary-text)' }}>
                    Metadata Discovery Only
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
};

