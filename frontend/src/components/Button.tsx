import React from 'react';

interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: 'primary' | 'secondary' | 'danger';
  size?: 'sm' | 'md';
}

export const Button: React.FC<ButtonProps> = ({
  children,
  variant = 'primary',
  size = 'md',
  style,
  disabled,
  ...props
}) => {
  const isSm = size === 'sm';

  const baseStyle: React.CSSProperties = {
    display: 'inline-flex',
    alignItems: 'center',
    justifyContent: 'center',
    borderRadius: 'var(--radius-control)',
    fontWeight: 500,
    fontSize: isSm ? '14px' : '15px',
    padding: isSm ? '6px 12px' : '10px 16px',
    minHeight: isSm ? '36px' : 'var(--input-height)',
    transition: 'background-color var(--duration-ms), opacity var(--duration-ms)',
    opacity: disabled ? 0.6 : 1,
    cursor: disabled ? 'not-allowed' : 'pointer',
    border: '1px solid transparent',
  };

  let variantStyle: React.CSSProperties = {};
  if (variant === 'primary') {
    variantStyle = {
      backgroundColor: 'var(--color-primary)',
      color: 'var(--color-primary-text)',
    };
  } else if (variant === 'secondary') {
    variantStyle = {
      backgroundColor: 'var(--color-surface)',
      color: 'var(--color-text)',
      borderColor: 'var(--color-border)',
    };
  } else if (variant === 'danger') {
    variantStyle = {
      backgroundColor: 'var(--color-danger)',
      color: '#FFFFFF',
    };
  }

  return (
    <button
      disabled={disabled}
      style={{ ...baseStyle, ...variantStyle, ...style }}
      {...props}
    >
      {children}
    </button>
  );
};

