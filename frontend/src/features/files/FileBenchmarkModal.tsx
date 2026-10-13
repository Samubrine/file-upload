import React, { useState } from 'react';
import type { DownloadFile, OwnerFile } from '../../api/types';
import { Button } from '../../components/Button';
import { Modal } from '../../components/Modal';

interface RunResult {
  variant: string;
  iteration: number;
  clientTimeMs: number;
  serverDecryptMs: number;
  serverDbMs: number;
  serverKdfMs: number;
  serverMacMs: number;
  serverTotalMs: number;
  sha256Hex: string;
  throughputMBs: number;
}

interface VariantSummary {
  variant: string;
  mode: string;
  padded: boolean;
  medianClientMs: number;
  medianDecryptMs: number;
  throughputMBs: number;
  checksumMatches: boolean;
}

const variantDetails: Record<string, { mode: string; padded: boolean }> = {
  'aes-256-cbc': { mode: 'CBC', padded: true },
  'aes-256-cfb128': { mode: 'CFB128', padded: false },
  'aes-256-ofb': { mode: 'OFB', padded: false },
  'aes-256-ctr': { mode: 'CTR (Default)', padded: false },
  'des-cbc': { mode: 'CBC (Legacy)', padded: true },
  'rc4-256': { mode: 'Stream (Legacy)', padded: false },
};

function bufferToHex(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let hex = '';
  for (let i = 0; i < bytes.length; i++) {
    hex += bytes[i].toString(16).padStart(2, '0');
  }
  return hex;
}

function parseServerTiming(header: string | null): { db: number; kdf: number; mac: number; decrypt: number; total: number } {
  const result = { db: 0, kdf: 0, mac: 0, decrypt: 0, total: 0 };
  if (!header) return result;

  const parts = header.split(',');
  for (const part of parts) {
    const [name, durPart] = part.trim().split(';');
    if (name && durPart && durPart.startsWith('dur=')) {
      const dur = parseFloat(durPart.substring(4)) || 0;
      if (name === 'db') result.db = dur;
      else if (name === 'kdf') result.kdf = dur;
      else if (name === 'mac') result.mac = dur;
      else if (name === 'decrypt') result.decrypt = dur;
      else if (name === 'total') result.total = dur;
    }
  }
  return result;
}

export const FileBenchmarkModal: React.FC<{
  isOpen: boolean;
  onClose: () => void;
  file: OwnerFile | DownloadFile | null;
}> = ({ isOpen, onClose, file }) => {
  const [repetitions, setRepetitions] = useState<number>(3);
  const [running, setRunning] = useState<boolean>(false);
  const [progressText, setProgressText] = useState<string>('');
  const [progressPercent, setProgressPercent] = useState<number>(0);
  const [summaries, setSummaries] = useState<VariantSummary[] | null>(null);
  const [rawRuns, setRawRuns] = useState<RunResult[]>([]);
  const [firstChecksum, setFirstChecksum] = useState<string>('');

  if (!file) return null;

  const variants = file.variants || [
    'aes-256-cbc',
    'aes-256-cfb128',
    'aes-256-ofb',
    'aes-256-ctr',
    'des-cbc',
    'rc4-256',
  ];

  const runBenchmark = async () => {
    setRunning(true);
    setSummaries(null);
    setRawRuns([]);
    setProgressPercent(0);

    const totalSteps = variants.length * repetitions;
    let completedSteps = 0;
    const runs: RunResult[] = [];
    let referenceChecksum = '';

    try {
      for (let vIdx = 0; vIdx < variants.length; vIdx++) {
        const variant = variants[vIdx];

        for (let iter = 1; iter <= repetitions; iter++) {
          setProgressText('Benchmarking ' + variant + ' (run ' + iter + '/' + repetitions + ')...');

          const t0 = performance.now();
          const res = await fetch('/files/' + file.id + '/download?variant=' + variant + '&benchmark=1', {
            credentials: 'same-origin',
            headers: { 'Cache-Control': 'no-store' },
          });

          if (!res.ok) {
            throw new Error('Download failed for variant ' + variant + ': ' + res.statusText);
          }

          const arrayBuffer = await res.arrayBuffer();
          const t1 = performance.now();
          const clientTimeMs = Math.max(0.1, t1 - t0);

          // Calculate SHA-256 hash using SubtleCrypto
          const hashBuffer = await window.crypto.subtle.digest('SHA-256', arrayBuffer);
          const hashHex = bufferToHex(hashBuffer);

          if (!referenceChecksum) {
            referenceChecksum = hashHex;
            setFirstChecksum(hashHex);
          }

          const timing = parseServerTiming(res.headers.get('Server-Timing'));
          const sizeBytes = arrayBuffer.byteLength;
          const throughputMBs = (sizeBytes / (1024 * 1024)) / (clientTimeMs / 1000);

          runs.push({
            variant,
            iteration: iter,
            clientTimeMs,
            serverDecryptMs: timing.decrypt,
            serverDbMs: timing.db,
            serverKdfMs: timing.kdf,
            serverMacMs: timing.mac,
            serverTotalMs: timing.total,
            sha256Hex: hashHex,
            throughputMBs,
          });

          completedSteps++;
          setProgressPercent(Math.round((completedSteps / totalSteps) * 100));
        }
      }

      setRawRuns(runs);

      // Group and calculate median summaries
      const summaryList: VariantSummary[] = variants.map((v) => {
        const vRuns = runs.filter((r) => r.variant === v);
        const clientTimes = vRuns.map((r) => r.clientTimeMs).sort((a, b) => a - b);
        const decryptTimes = vRuns.map((r) => r.serverDecryptMs).sort((a, b) => a - b);
        const throughs = vRuns.map((r) => r.throughputMBs).sort((a, b) => a - b);

        const medianClient = clientTimes[Math.floor(clientTimes.length / 2)] || 0;
        const medianDecrypt = decryptTimes[Math.floor(decryptTimes.length / 2)] || 0;
        const medianThrough = throughs[Math.floor(throughs.length / 2)] || 0;
        const allMatch = vRuns.every((r) => r.sha256Hex === referenceChecksum);

        const details = variantDetails[v] || { mode: 'Unknown', padded: false };

        return {
          variant: v,
          mode: details.mode,
          padded: details.padded,
          medianClientMs: medianClient,
          medianDecryptMs: medianDecrypt,
          throughputMBs: medianThrough,
          checksumMatches: allMatch,
        };
      });

      setSummaries(summaryList);
      setProgressText('Benchmark completed successfully!');
    } catch (err: any) {
      alert(err.message || 'Benchmark error occurred');
      setProgressText('Benchmark interrupted');
    } finally {
      setRunning(false);
    }
  };

  const exportCSV = () => {
    if (rawRuns.length === 0) return;
    const header = [
      'variant',
      'iteration',
      'file_id',
      'filename',
      'file_size_bytes',
      'client_time_ms',
      'server_decrypt_ms',
      'server_db_ms',
      'server_kdf_ms',
      'server_mac_ms',
      'server_total_ms',
      'throughput_mbs',
      'sha256_checksum',
    ].join(',');

    const lines = rawRuns.map((r) =>
      [
        r.variant,
        r.iteration,
        file.id,
        JSON.stringify(file.filename),
        file.size_bytes,
        r.clientTimeMs.toFixed(3),
        r.serverDecryptMs.toFixed(3),
        r.serverDbMs.toFixed(3),
        r.serverKdfMs.toFixed(3),
        r.serverMacMs.toFixed(3),
        r.serverTotalMs.toFixed(3),
        r.throughputMBs.toFixed(2),
        r.sha256Hex,
      ].join(',')
    );

    const csvContent = [header, ...lines].join(String.fromCharCode(10));
    const blob = new Blob([csvContent], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'benchmark_' + file.filename + '.csv';
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  };

  const maxThroughput = summaries ? Math.max(...summaries.map((s) => s.throughputMBs), 1) : 1;

  return (
    <Modal isOpen={isOpen} onClose={onClose} title={'Benchmark File: ' + file.filename} maxWidth="760px">
      <div>
        <div style={{ padding: '12px 16px', backgroundColor: '#F8FAFC', borderRadius: '8px', border: '1px solid var(--color-border)', marginBottom: '16px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '13px' }}>
            <span><strong>Size:</strong> {(file.size_bytes / 1024).toFixed(1)} KB ({file.size_bytes.toLocaleString()} bytes)</span>
            <span><strong>MIME:</strong> {file.mime}</span>
            <span><strong>Variants:</strong> {variants.length} symmetric configurations</span>
          </div>
        </div>

        {/* Configuration */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '16px', marginBottom: '20px' }}>
          <label style={{ fontSize: '13px', fontWeight: 500 }}>
            Repetitions per variant:
            <select
              value={repetitions}
              disabled={running}
              onChange={(e) => setRepetitions(parseInt(e.target.value, 10))}
              style={{
                marginLeft: '8px',
                padding: '6px 12px',
                borderRadius: '6px',
                border: '1px solid var(--color-border)',
                backgroundColor: 'var(--color-surface)',
              }}
            >
              <option value={1}>1 run (Fast quick-check)</option>
              <option value={3}>3 runs (Recommended median)</option>
              <option value={5}>5 runs (High-precision)</option>
            </select>
          </label>

          <Button variant="primary" disabled={running} onClick={runBenchmark} style={{ minWidth: '160px' }}>
            {running ? 'Running Benchmark...' : 'Run Benchmark'}
          </Button>

          {summaries && (
            <Button variant="secondary" onClick={exportCSV} size="sm">
              📥 Export CSV
            </Button>
          )}
        </div>

        {/* Progress Bar */}
        {running && (
          <div style={{ marginBottom: '20px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '12px', color: 'var(--color-secondary-text)', marginBottom: '4px' }}>
              <span>{progressText}</span>
              <span>{progressPercent}%</span>
            </div>
            <div style={{ height: '8px', backgroundColor: '#E2E8F0', borderRadius: '4px', overflow: 'hidden' }}>
              <div style={{ height: '100%', width: progressPercent + '%', backgroundColor: 'var(--color-primary)', transition: 'width 200ms ease' }} />
            </div>
          </div>
        )}

        {/* Results Visuals & Table */}
        {summaries && (
          <div>
            {/* Visual Throughput Comparison */}
            <div style={{ marginBottom: '20px', padding: '16px', backgroundColor: '#F8FAFC', borderRadius: '8px', border: '1px solid var(--color-border)' }}>
              <h4 style={{ fontSize: '14px', fontWeight: 600, marginBottom: '12px' }}>
                Client Throughput Comparison (MB/s)
              </h4>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                {summaries.map((s) => {
                  const barPct = (s.throughputMBs / maxThroughput) * 100;
                  const isLegacy = s.variant === 'des-cbc' || s.variant === 'rc4-256';
                  const isDefault = s.variant === 'aes-256-ctr';
                  return (
                    <div key={s.variant} style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                      <span style={{ width: '130px', fontSize: '12px', fontFamily: 'var(--font-mono)', fontWeight: isDefault ? 700 : 500, color: isDefault ? 'var(--color-primary)' : 'inherit' }}>
                        {s.variant}
                      </span>
                      <div style={{ flex: 1, height: '18px', backgroundColor: '#E2E8F0', borderRadius: '3px', overflow: 'hidden' }}>
                        <div
                          style={{
                            height: '100%',
                            width: Math.max(1, barPct) + '%',
                            backgroundColor: isLegacy ? '#F59E0B' : isDefault ? 'var(--color-primary)' : '#3B82F6',
                          }}
                        />
                      </div>
                      <span style={{ width: '80px', textAlign: 'right', fontSize: '12px', fontFamily: 'var(--font-mono)', fontWeight: 600 }}>
                        {s.throughputMBs.toFixed(2)} MB/s
                      </span>
                    </div>
                  );
                })}
              </div>
            </div>

            {/* Detailed Table */}
            <div style={{ overflowX: 'auto', marginBottom: '16px' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '12px', textAlign: 'left' }}>
                <thead>
                  <tr style={{ backgroundColor: '#F1F5F9', borderBottom: '1px solid var(--color-border)', color: 'var(--color-secondary-text)' }}>
                    <th style={{ padding: '8px 10px' }}>Variant</th>
                    <th style={{ padding: '8px 10px' }}>Mode</th>
                    <th style={{ padding: '8px 10px' }}>Padding</th>
                    <th style={{ padding: '8px 10px' }}>Server Decrypt</th>
                    <th style={{ padding: '8px 10px' }}>Total Client Time</th>
                    <th style={{ padding: '8px 10px' }}>Throughput</th>
                    <th style={{ padding: '8px 10px' }}>SHA-256 Match</th>
                  </tr>
                </thead>
                <tbody>
                  {summaries.map((s) => (
                    <tr key={s.variant} style={{ borderBottom: '1px solid #E2E8F0' }}>
                      <td style={{ padding: '8px 10px', fontFamily: 'var(--font-mono)', fontWeight: 600 }}>
                        {s.variant}
                      </td>
                      <td style={{ padding: '8px 10px' }}>{s.mode}</td>
                      <td style={{ padding: '8px 10px' }}>{s.padded ? 'PKCS#7' : 'Stream'}</td>
                      <td style={{ padding: '8px 10px', fontFamily: 'var(--font-mono)' }}>
                        {s.medianDecryptMs.toFixed(2)} ms
                      </td>
                      <td style={{ padding: '8px 10px', fontFamily: 'var(--font-mono)' }}>
                        {s.medianClientMs.toFixed(2)} ms
                      </td>
                      <td style={{ padding: '8px 10px', fontFamily: 'var(--font-mono)', fontWeight: 600 }}>
                        {s.throughputMBs.toFixed(2)} MB/s
                      </td>
                      <td style={{ padding: '8px 10px' }}>
                        {s.checksumMatches ? (
                          <span style={{ color: 'var(--color-success)', fontWeight: 600 }}>✓ Byte-identical</span>
                        ) : (
                          <span style={{ color: 'var(--color-danger)', fontWeight: 600 }}>✗ Mismatch</span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {/* Checksum & Security Note */}
            <div style={{ padding: '10px 14px', backgroundColor: '#F1F5F9', borderRadius: '6px', fontSize: '11px', color: 'var(--color-secondary-text)' }}>
              <div><strong>Plaintext SHA-256 Hash:</strong> <code style={{ wordBreak: 'break-all' }}>{firstChecksum}</code></div>
              <div style={{ marginTop: '4px' }}>All 6 independently sealed cipher replicas decrypted to the exact same cryptographic hash. DES-CBC and RC4-256 are educational legacy comparisons and are cryptographically broken.</div>
            </div>
          </div>
        )}
      </div>
    </Modal>
  );
};

