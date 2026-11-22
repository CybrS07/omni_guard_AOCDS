import { useRef, useState } from 'react'

const W = 640
const H = 170
const PAD = { l: 44, r: 8, t: 8, b: 18 }

/**
 * series: [{ key, label, color, data: number[] }]  (all the same length, oldest first)
 * fmt: value -> string      max: fixed y max (e.g. 100); otherwise auto
 */
export default function AreaChart({ series, fmt = (v) => v.toFixed(0), max, stepSecs = 1 }) {
  const ref = useRef(null)
  const [hover, setHover] = useState(null)
  const n = Math.max(2, ...series.map((s) => s.data.length))
  const peak = Math.max(1e-9, ...series.flatMap((s) => s.data.filter((v) => v != null)))
  const top = max ?? niceCeil(peak)
  const x = (i, len) => PAD.l + ((i + (n - len)) / (n - 1)) * (W - PAD.l - PAD.r)
  const y = (v) => PAD.t + (1 - Math.min(v, top) / top) * (H - PAD.t - PAD.b)

  const paths = series.map((s) => {
    const pts = s.data.map((v, i) => [x(i, s.data.length), y(v ?? 0)])
    if (!pts.length) return { line: '', area: '' }
    const line = pts.map((p, i) => `${i ? 'L' : 'M'}${p[0].toFixed(1)} ${p[1].toFixed(1)}`).join(' ')
    const area = `${line} L${pts[pts.length - 1][0].toFixed(1)} ${H - PAD.b} L${pts[0][0].toFixed(1)} ${H - PAD.b} Z`
    return { line, area }
  })

  const onMove = (e) => {
    const box = ref.current.getBoundingClientRect()
    const px = ((e.clientX - box.left) / box.width) * W
    const i = Math.round(((px - PAD.l) / (W - PAD.l - PAD.r)) * (n - 1))
    setHover(Math.max(0, Math.min(n - 1, i)))
  }

  const hi = hover
  return (
    <div className="chart" ref={ref} onMouseMove={onMove} onMouseLeave={() => setHover(null)}>
      <svg viewBox={`0 0 ${W} ${H}`} role="img">
        <defs>
          {series.map((s) => (
            <linearGradient id={`g-${s.key}`} key={s.key} x1="0" y1="0" x2="0" y2="1">
              <stop offset="0" stopColor={s.color} stopOpacity=".35" />
              <stop offset="1" stopColor={s.color} stopOpacity="0" />
            </linearGradient>
          ))}
        </defs>
        {[0, 0.5, 1].map((f) => (
          <g key={f}>
            <line x1={PAD.l} x2={W - PAD.r} y1={y(top * f)} y2={y(top * f)} stroke="var(--line)" strokeDasharray="3 5" />
            <text x={PAD.l - 6} y={y(top * f) + 3} textAnchor="end">{fmt(top * f)}</text>
          </g>
        ))}
        <text x={PAD.l} y={H - 3}>-{Math.round((n - 1) * stepSecs)}s</text>
        <text x={W - PAD.r} y={H - 3} textAnchor="end">now</text>
        {series.map((s, k) => (
          <g key={s.key}>
            <path d={paths[k].area} fill={`url(#g-${s.key})`} />
            <path d={paths[k].line} fill="none" stroke={s.color} strokeWidth="2" strokeLinejoin="round" />
          </g>
        ))}
        {hi != null && (
          <line x1={PAD.l + (hi / (n - 1)) * (W - PAD.l - PAD.r)} x2={PAD.l + (hi / (n - 1)) * (W - PAD.l - PAD.r)} y1={PAD.t} y2={H - PAD.b} stroke="var(--muted)" strokeOpacity=".6" />
        )}
      </svg>
      {hi != null && (
        <div className="tip" style={{ left: `${((PAD.l + (hi / (n - 1)) * (W - PAD.l - PAD.r)) / W) * 100}%` }}>
          {series.map((s) => {
            const v = s.data[hi - (n - s.data.length)]
            return v == null ? null : (
              <div key={s.key} style={{ color: s.color }}>{s.label}: {fmt(v)}</div>
            )
          })}
        </div>
      )}
    </div>
  )
}

function niceCeil(v) {
  const p = 10 ** Math.floor(Math.log10(v))
  const m = v / p
  return (m <= 1 ? 1 : m <= 2 ? 2 : m <= 5 ? 5 : 10) * p
}
