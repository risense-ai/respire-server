export function Brand({ href = '/', light = false }) {
  return (
    <a className={`respire-logo ${light ? 'light' : ''}`} href={href} aria-label="Respire home">
      <svg viewBox="0 0 52 44" aria-hidden="true">
        <path d="M3 23C10 22 9 6 18 7S32 40 41 36c4-2 6-8 8-12" fill="none" stroke="currentColor" strokeWidth="1.7" />
        <path d="M3 25C9 14 13 10 19 14s11 24 20 20c5-2 7-6 10-9" fill="none" stroke="#a93021" strokeWidth="1.4" />
      </svg>
      <span>respire<span className="logo-period">.</span></span>
    </a>
  );
}
