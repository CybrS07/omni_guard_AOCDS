import Icon from './Icon.jsx'

/** Required wording from the NVD terms. Shown wherever NVD data appears. NVD text is displayed exactly as published. */
export default function NvdNotice({ compact = false }) {
  return (
    <div role="note" className="nvd-notice" style={{ display: 'flex', gap: 8, alignItems: 'center', padding: compact ? '6px 10px' : '10px 12px', border: '1px solid var(--line)', borderRadius: 10, background: 'var(--inset)', fontSize: 12.5 }}>
      <Icon name="database" size={16} />
      <span>This product uses the NVD API but is not endorsed or certified by the NVD.</span>
    </div>
  )
}
