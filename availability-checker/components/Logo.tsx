export default function Logo({ size = 28 }: { size?: number }) {
  return (
    <svg viewBox="0 0 64 64" width={size} height={size} aria-hidden>
      <rect width="64" height="64" rx="16" fill="var(--accent)" />
      <path d="M19 48V17l26 31V30" fill="none" stroke="var(--accent-ink)" strokeWidth="7" strokeLinecap="round" strokeLinejoin="round" />
      <circle cx="45" cy="17" r="4.5" fill="#5eead4" />
    </svg>
  );
}
