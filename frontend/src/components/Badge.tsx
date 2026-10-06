import React from 'react';

export type BadgeType = 'private' | 'listed' | 'metadata' | 'download';

interface BadgeProps {
  type: BadgeType;
}

export const Badge: React.FC<BadgeProps> = ({ type }) => {
  const styles: Record<BadgeType, { label: string; bg: string; color: string; border: string }> = {
    private: {
      label: 'Private',
      bg: '#F1F5F9',
      color: '#475569',
      border: '#CBD5E1',
    },
    listed: {
      label: 'Listed',
      bg: '#EFF6FF',
      color: '#1D4ED8',
      border: '#BFDBFE',
    },
    metadata: {
      label: 'Metadata Access',
      bg: '#FEF3C7',
      color: '#92400E',
      border: '#FDE68A',
    },
    download: {
      label: 'Download Access',
      bg: '#DCFCE7',
      color: '#166534',
      border: '#BBF7D0',
    },
  };

  const current = styles[type];

  return (
    <span
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        padding: '2px 8px',
        fontSize: '12px',
        fontWeight: 500,
        borderRadius: '9999px',
        backgroundColor: current.bg,
        color: current.color,
        border: '1px solid ' + current.border,
        whiteSpace: 'nowrap',
      }}
    >
      {current.label}
    </span>
  );
};

