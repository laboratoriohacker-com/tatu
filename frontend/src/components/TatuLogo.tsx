export function TatuLogo({ size = 32 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 40 40" fill="none">
      <path d="M20 4L34 12V28L20 36L6 28V12L20 4Z" stroke="#10B981" strokeWidth="1.5" fill="none" opacity="0.6" />
      <path d="M20 8L30 14V26L20 32L10 26V14L20 8Z" stroke="#10B981" strokeWidth="1.5" fill="rgba(16,185,129,0.15)" />
      <path d="M20 12L26 16V24L20 28L14 24V16L20 12Z" fill="#10B981" opacity="0.3" />
      <circle cx="20" cy="20" r="3" fill="#10B981" />
      <line x1="20" y1="8" x2="20" y2="12" stroke="#10B981" strokeWidth="1" opacity="0.5" />
      <line x1="10" y1="14" x2="14" y2="16" stroke="#10B981" strokeWidth="1" opacity="0.5" />
      <line x1="30" y1="14" x2="26" y2="16" stroke="#10B981" strokeWidth="1" opacity="0.5" />
      <line x1="10" y1="26" x2="14" y2="24" stroke="#10B981" strokeWidth="1" opacity="0.5" />
      <line x1="30" y1="26" x2="26" y2="24" stroke="#10B981" strokeWidth="1" opacity="0.5" />
      <line x1="20" y1="32" x2="20" y2="28" stroke="#10B981" strokeWidth="1" opacity="0.5" />
    </svg>
  );
}
