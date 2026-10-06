import React, { useState } from 'react';
import benchmarkData from '../../data/benchmarkSummary.json';

interface BenchmarkItem {
  fixture_id: string;
  variant_id: string;
  n: number;
  successes: number;
  failures: number;
  plaintext_bytes: number;
  ciphertext_bytes: number;
  envelope_bytes: number;
  seal_median_ns: number;
  seal_p95_ns: number;
  decrypt_median_ns: number;
  decrypt_p95_ns: number;
  client_download_median_ns: number;
  client_download_p95_ns: number;
  throughput_mib_s: number;
}

const variantMeta: Record<string, { keyBits: number; blockSize: string; mode: string; padded: boolean; status: string }> = {
  'aes-128-cbc': { keyBits: 128, blockSize: '16 B', mode: 'CBC', padded: true, status: 'Standard' },
  'aes-128-cfb128': { keyBits: 128, blockSize: '16 B', mode: 'CFB128', padded: false, status: 'Standard' },
  'aes-128-ofb': { keyBits: 128, blockSize: '16 B', mode: 'OFB', padded: false, status: 'Standard' },
  'aes-128-ctr': { keyBits: 128, blockSize: '16 B', mode: 'CTR', padded: false, status: 'Standard' },

  'aes-192-cbc': { keyBits: 192, blockSize: '16 B', mode: 'CBC', padded: true, status: 'Standard' },
  'aes-192-cfb128': { keyBits: 192, blockSize: '16 B', mode: 'CFB128', padded: false, status: 'Standard' },
  'aes-192-ofb': { keyBits: 192, blockSize: '16 B', mode: 'OFB', padded: false, status: 'Standard' },
  'aes-192-ctr': { keyBits: 192, blockSize: '16 B', mode: 'CTR', padded: false, status: 'Standard' },

  'aes-256-cbc': { keyBits: 256, blockSize: '16 B', mode: 'CBC', padded: true, status: 'Standard' },
  'aes-256-cfb128': { keyBits: 256, blockSize: '16 B', mode: 'CFB128', padded: false, status: 'Standard' },
  'aes-256-ofb': { keyBits: 256, blockSize: '16 B', mode: 'OFB', padded: false, status: 'Standard' },
  'aes-256-ctr': { keyBits: 256, blockSize: '16 B', mode: 'CTR', padded: false, status: 'Default' },

  'des-cbc': { keyBits: 56, blockSize: '8 B', mode: 'CBC', padded: true, status: 'Broken (Legacy)' },
  'rc4-256': { keyBits: 256, blockSize: 'Stream', mode: 'Stream', padded: false, status: 'Broken (Legacy)' },
};

export const BenchmarkView: React.FC = () => {
  const items = benchmarkData as BenchmarkItem[];
  const fixtureIDs = Array.from(new Set(items.map((i) => i.fixture_id)));
  const [selectedFixture, setSelectedFixture] = useState<string>(
    fixtureIDs.includes('binary-1mib') ? 'binary-1mib' : fixtureIDs[0] || ''
  );

  const fixtureItems = items.filter((i) => i.fixture_id === selectedFixture);

  const maxThroughput = Math.max(...fixtureItems.map((i) => i.throughput_mib_s), 1);

  const formatNs = (ns: number) => {
    if (ns === 0) return '< 1 μs';
    if (ns < 1_000_000) return (ns / 1_000).toFixed(1) + ' μs';
    return (ns / 1_000_000).toFixed(2) + ' ms';
  };

  return (
    <div>
      <div style={{ marginBottom: '24px' }}>
        <h2 style={{ fontSize: '20px', fontWeight: 600, color: 'var(--color-text)' }}>
          14-Variant Cryptographic Benchmark & Comparison
        </h2>
        <p style={{ fontSize: '14px', color: 'var(--color-secondary-text)', marginTop: '4px' }}>
          Empirical measurements comparing 14 independently encrypted copies of identical plaintexts. Evaluation across 3 AES key sizes (128, 192, 256 bits) crossed with 4 modes (CBC, CFB128, OFB, CTR), plus legacy references DES-CBC and RC4-256.
        </p>
      </div>

      {/* Fixture Selector Tabs */}
      <div style={{ display: 'flex', gap: '8px', overflowX: 'auto', marginBottom: '20px', paddingBottom: '4px' }}>
        {fixtureIDs.map((fID) => (
          <button
            key={fID}
            onClick={() => setSelectedFixture(fID)}
            style={{
              padding: '8px 16px',
              borderRadius: 'var(--radius-control)',
              fontSize: '13px',
              fontWeight: 500,
              backgroundColor: selectedFixture === fID ? 'var(--color-primary)' : 'var(--color-surface)',
              color: selectedFixture === fID ? '#FFFFFF' : 'var(--color-text)',
              border: '1px solid ' + (selectedFixture === fID ? 'var(--color-primary)' : 'var(--color-border)'),
              whiteSpace: 'nowrap',
            }}
          >
            {fID}
          </button>
        ))}
      </div>

      {/* Visual Throughput Comparison */}
      <div
        style={{
          backgroundColor: 'var(--color-surface)',
          borderRadius: 'var(--radius-panel)',
          border: '1px solid var(--color-border)',
          padding: '24px',
          marginBottom: '24px',
        }}
      >
        <h3 style={{ fontSize: '16px', fontWeight: 600, marginBottom: '4px' }}>
          Throughput Comparison (MiB/s) — {selectedFixture}
        </h3>
        <p style={{ fontSize: '13px', color: 'var(--color-secondary-text)', marginBottom: '20px' }}>
          Measured from 30 repeated authorized client HTTP downloads after warmups.
        </p>

        <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
          {fixtureItems.map((item) => {
            const meta = variantMeta[item.variant_id] || { keyBits: 0, mode: '', status: '' };
            const barPct = (item.throughput_mib_s / maxThroughput) * 100;
            const isBroken = meta.status.includes('Broken');
            const isDefault = meta.status === 'Default';

            return (
              <div key={item.variant_id} style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                <div style={{ width: '140px', fontFamily: 'var(--font-mono)', fontSize: '13px', fontWeight: isDefault ? 700 : 500, color: isDefault ? 'var(--color-primary)' : 'inherit' }}>
                  {item.variant_id}
                </div>
                <div style={{ flex: 1, backgroundColor: '#F1F5F9', height: '22px', borderRadius: '4px', overflow: 'hidden', position: 'relative' }}>
                  <div
                    style={{
                      height: '100%',
                      width: Math.max(1, barPct) + '%',
                      backgroundColor: isBroken ? '#F59E0B' : isDefault ? 'var(--color-primary)' : '#3B82F6',
                      transition: 'width 300ms ease',
                    }}
                  />
                </div>
                <div style={{ width: '85px', textAlign: 'right', fontSize: '13px', fontWeight: 600, fontFamily: 'var(--font-mono)' }}>
                  {item.throughput_mib_s.toFixed(2)} MB/s
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Detailed Measurements Table */}
      <div
        style={{
          backgroundColor: 'var(--color-surface)',
          borderRadius: 'var(--radius-panel)',
          border: '1px solid var(--color-border)',
          overflow: 'hidden',
          marginBottom: '24px',
        }}
      >
        <div style={{ padding: '16px 20px', borderBottom: '1px solid var(--color-border)' }}>
          <h3 style={{ fontSize: '16px', fontWeight: 600 }}>Detailed Cryptographic & Overhead Metrics</h3>
        </div>

        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '13px' }}>
            <thead>
              <tr style={{ backgroundColor: '#F8FAFC', borderBottom: '1px solid var(--color-border)', color: 'var(--color-secondary-text)' }}>
                <th style={{ padding: '12px 14px' }}>Variant</th>
                <th style={{ padding: '12px 14px' }}>Key / Mode</th>
                <th style={{ padding: '12px 14px' }}>Padding</th>
                <th style={{ padding: '12px 14px' }}>Ciphertext</th>
                <th style={{ padding: '12px 14px' }}>Total Envelope</th>
                <th style={{ padding: '12px 14px' }}>Seal Median</th>
                <th style={{ padding: '12px 14px' }}>Decrypt Median</th>
                <th style={{ padding: '12px 14px' }}>Full Download Median</th>
                <th style={{ padding: '12px 14px' }}>Integrity</th>
              </tr>
            </thead>
            <tbody>
              {fixtureItems.map((item) => {
                const meta = variantMeta[item.variant_id] || { keyBits: 0, mode: '', padded: false, status: '' };
                const overheadBytes = item.envelope_bytes - item.ciphertext_bytes;

                return (
                  <tr key={item.variant_id} style={{ borderBottom: '1px solid #F1F5F9' }}>
                    <td style={{ padding: '12px 14px', fontFamily: 'var(--font-mono)', fontWeight: 600 }}>
                      {item.variant_id}
                    </td>
                    <td style={{ padding: '12px 14px' }}>
                      {meta.keyBits} bits • {meta.mode}
                    </td>
                    <td style={{ padding: '12px 14px' }}>
                      {meta.padded ? 'PKCS#7' : 'None (Stream)'}
                    </td>
                    <td style={{ padding: '12px 14px', fontFamily: 'var(--font-mono)' }}>
                      {item.ciphertext_bytes.toLocaleString()} B
                    </td>
                    <td style={{ padding: '12px 14px', fontFamily: 'var(--font-mono)' }}>
                      {item.envelope_bytes.toLocaleString()} B <span style={{ color: 'var(--color-secondary-text)', fontSize: '11px' }}>(+{overheadBytes}B)</span>
                    </td>
                    <td style={{ padding: '12px 14px', fontFamily: 'var(--font-mono)' }}>
                      {formatNs(item.seal_median_ns)}
                    </td>
                    <td style={{ padding: '12px 14px', fontFamily: 'var(--font-mono)' }}>
                      {formatNs(item.decrypt_median_ns)}
                    </td>
                    <td style={{ padding: '12px 14px', fontFamily: 'var(--font-mono)', fontWeight: 600 }}>
                      {formatNs(item.client_download_median_ns)}
                    </td>
                    <td style={{ padding: '12px 14px' }}>
                      <span style={{ color: item.failures === 0 ? 'var(--color-success)' : 'var(--color-danger)', fontWeight: 600 }}>
                        {item.successes}/{item.n} OK
                      </span>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>

      {/* Security Analysis & Educational Disclosures */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))',
          gap: '20px',
        }}
      >
        <div
          style={{
            backgroundColor: '#EFF6FF',
            borderRadius: 'var(--radius-panel)',
            border: '1px solid #BFDBFE',
            padding: '20px',
          }}
        >
          <h4 style={{ fontSize: '15px', fontWeight: 600, color: '#1E40AF', marginBottom: '8px' }}>
            EtM Authenticated Framing
          </h4>
          <p style={{ fontSize: '13px', color: '#1E3A8A', lineHeight: 1.5 }}>
            Every variant uses an Encrypt-then-MAC (EtM) envelope. A distinct HMAC-SHA256 tag authenticates the envelope framing, version, context parameters (owner, payload ID, file ID, revision), and ciphertext before any decryption occurs. This ensures fail-closed integrity against ciphertext and padding manipulation.
          </p>
        </div>

        <div
          style={{
            backgroundColor: '#FEF3C7',
            borderRadius: 'var(--radius-panel)',
            border: '1px solid #FDE68A',
            padding: '20px',
          }}
        >
          <h4 style={{ fontSize: '15px', fontWeight: 600, color: '#92400E', marginBottom: '8px' }}>
            Legacy Algorithm Warnings
          </h4>
          <p style={{ fontSize: '13px', color: '#78350F', lineHeight: 1.5 }}>
            Single DES (56 effective bits) is vulnerable to brute-force key search within hours. RC4 exhibits severe statistical keystream biases and plaintext recovery vulnerabilities. Both ciphers are included strictly for historical and academic evaluation, and should never be deployed for real personal data protection.
          </p>
        </div>

        <div
          style={{
            backgroundColor: 'var(--color-surface)',
            borderRadius: 'var(--radius-panel)',
            border: '1px solid var(--color-border)',
            padding: '20px',
          }}
        >
          <h4 style={{ fontSize: '15px', fontWeight: 600, color: 'var(--color-text)', marginBottom: '8px' }}>
            Performance & Padding Behavior
          </h4>
          <p style={{ fontSize: '13px', color: 'var(--color-secondary-text)', lineHeight: 1.5 }}>
            CBC mode always adds 1 to block_size bytes of PKCS#7 padding, resulting in slightly larger ciphertexts. Stream modes (CTR, OFB, CFB128) and RC4 preserve exact plaintext byte count. AES hardware acceleration (AES-NI) typically allows AES-256 to outperform unaccelerated legacy DES even with a larger key space.
          </p>
        </div>
      </div>
    </div>
  );
};

