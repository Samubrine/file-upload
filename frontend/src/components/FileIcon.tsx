import React from 'react';

export const FileIcon: React.FC<{ filename: string; size?: number }> = ({ filename, size = 20 }) => {
  const ext = filename.split('.').pop()?.toLowerCase() || '';

  let color = '#64748B';
  let label = 'FILE';

  if (['png', 'jpg', 'jpeg', 'webp'].includes(ext)) {
    color = '#0284C7';
    label = 'IMG';
  } else if (ext === 'pdf') {
    color = '#DC2626';
    label = 'PDF';
  } else if (['doc', 'docx'].includes(ext)) {
    color = '#2563EB';
    label = 'DOC';
  } else if (['xls', 'xlsx'].includes(ext)) {
    color = '#16A34A';
    label = 'XLS';
  } else if (['mp4', 'webm', 'mov'].includes(ext)) {
    color = '#9333EA';
    label = 'VID';
  }

  return (
    <div
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        justifyContent: 'center',
        width: size + 10,
        height: size + 10,
        borderRadius: '6px',
        backgroundColor: '#F1F5F9',
        border: '1px solid #E2E8F0',
        color,
        fontSize: '10px',
        fontWeight: 700,
        letterSpacing: '0.5px',
        userSelect: 'none',
        flexShrink: 0,
      }}
      title={ext.toUpperCase()}
    >
      {label}
    </div>
  );
};

