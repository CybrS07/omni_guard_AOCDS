const COLORS = { idle: 'var(--idle)', normal: 'var(--chart-1)', high: 'var(--warn)', critical: 'var(--danger)' }

export default function Gauge({ value = 0, status = 'normal', label, size = 92 }) {
  const r = 38
  const c = 2 * Math.PI * r
  const v = Math.max(0, Math.min(100, value))
  return (
    <svg className="gauge" width={size} height={size} viewBox="0 0 100 100" role="img" aria-label={`${label || ''} ${v.toFixed(0)} percent`}>
      <circle cx="50" cy="50" r={r} fill="none" stroke="color-mix(in srgb, var(--tint) 35%, transparent)" strokeWidth="9" />
      <circle
        cx="50" cy="50" r={r} fill="none" stroke={COLORS[status] || COLORS.normal} strokeWidth="9" strokeLinecap="round"
        strokeDasharray={`${(c * v) / 100} ${c}`} transform="rotate(-90 50 50)"
        style={{ transition: 'stroke-dasharray .5s, stroke .3s', filter: `drop-shadow(0 0 5px ${COLORS[status] || COLORS.normal})` }}
      />
      <text x="50" y="55" textAnchor="middle" fontSize="20" fontWeight="700">{v.toFixed(0)}%</text>
    </svg>
  )
}
