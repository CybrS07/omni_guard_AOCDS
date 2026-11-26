import { Fragment, useState } from 'react'
import { api, usePoll } from '../api.js'
import Button from '../components/Button.jsx'
import { Confirm, useToast } from '../components/Feedback.jsx'
import ExportBar from '../components/ExportBar.jsx'
import Icon from '../components/Icon.jsx'
import { Bars } from '../components/Loader.jsx'
import { clock } from '../format.js'
import { copyText } from '../export.js'
import CheckServices from '../components/CheckServices.jsx'
import ContentReport from '../components/ContentReport.jsx'

const STATUS = {
  analyzing: ['info', 'Checking…'],
  awaiting_user: ['critical', 'Needs your decision'],
  allowed: ['ok', 'Saved (clean)'],
  allowed_vulnerable: ['warn', 'Saved (has vulnerabilities)'],
  allowed_by_user: ['warn', 'Allowed by you'],
  removed: ['critical', 'Removed'],
  error: ['warn', 'Error'],
}
const VERDICT = { clean: 'ok', vulnerable: 'warn', suspicious: 'high', malware: 'critical', unverified: 'warn' }

const flatDownload = (i) => ({
  detected_at: i.detected_at, name: i.name, status: i.status, verdict: i.verdict?.verdict || '', summary: i.verdict?.summary || '',
  version: i.info.version, product: i.info.product, publisher: i.info.company, size_bytes: i.info.size, sha256: i.info.sha256,
  signature: i.info.signature_status, signer: i.info.signer, location: i.original_path,
  vt_malicious: i.verdict?.vt?.malicious ?? '', vt_suspicious: i.verdict?.vt?.suspicious ?? '', vt_report: i.verdict?.vt?.link || '',
  cve_count: i.verdict?.cve_count ?? '', max_cvss: i.verdict?.max_score ?? '', fixed_in: i.verdict?.fixed_in || '',
  cves: (i.verdict?.cves || []).map((c) => c.id).join(' '),
})

export default function Downloads() {
  const { data, error, reload } = usePoll('/downloads', 3000)
  const toast = useToast()
  const [open, setOpen] = useState(null)
  const [ask, setAsk] = useState(null) // {item, allow}
  const [busy, setBusy] = useState(false)

  const decide = async () => {
    setBusy(true)
    try {
      await api('/downloads/decision', { method: 'POST', body: { id: ask.item.id, allow: ask.allow } })
      toast(ask.allow ? `${ask.item.name} allowed and saved` : `${ask.item.name} removed completely`)
      setAsk(null)
      reload()
    } catch (e) {
      toast(e.message, 'err')
      setAsk(null)
      reload()
    } finally {
      setBusy(false)
    }
  }

  // Delete the file (if still there) and forget the entry
  const [removing, setRemoving] = useState(null)
  const removeEntry = async () => {
    setBusy(true)
    try {
      const answer = await api('/downloads/remove', { method: 'POST', body: { id: removing.id } })
      toast(answer.message)
      reload()
    } catch (e) {
      toast(e.message, 'err')
    } finally {
      setBusy(false)
      setRemoving(null)
    }
  }

  const items = data?.items || []
  const waiting = items.filter((i) => i.status === 'awaiting_user')

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Downloads</h1>
          <p>New programs are isolated, checked against VirusTotal and NVD, then saved or held for you</p>
        </div>
        <Button icon="refresh" onClick={reload}>Refresh</Button>
      </div>

      {error && <div className="empty">{error.message}</div>}
      {!data && !error && <div className="empty"><Bars /></div>}

      {waiting.map((i) => (
        <div key={i.id} className="panel" style={{ borderColor: 'var(--danger)', marginBottom: 16 }}>
          <div className="panel-head"><h2><Icon name="alertTriangle" size={20} /> {i.name} is held in isolation</h2></div>
          <p style={{ margin: '0 0 12px' }}>{i.note}</p>
          <div className="toolbar">
            <Button onClick={() => setAsk({ item: i, allow: true })}>Allow (keep the file)</Button>
            <Button tone="danger" onClick={() => setAsk({ item: i, allow: false })}>Remove completely</Button>
          </div>
        </div>
      ))}

      <div className="panel" style={{ marginBottom: 16 }}>
        <div className="panel-head">
          <h2><Icon name="download" size={20} /> Recent downloads</h2>
          <ExportBar name="downloads" rows={items.map(flatDownload)} full={items} />
          {data && <span className="hint">watching {data.watching.length} folder{data.watching.length === 1 ? '' : 's'}{data.enabled ? '' : ' (monitor is switched off in config.json)'}</span>}
        </div>
        <div className="table-wrap">
          <table>
            <thead><tr><th>Time</th><th>File</th><th>Version</th><th>Result</th><th>Status</th><th /></tr></thead>
            <tbody>
              {items.map((i) => {
                const v = i.verdict?.verdict
                const [tone, label] = STATUS[i.status] || ['info', i.status]
                return (
                  <Fragment key={i.id}>
                    <tr onClick={() => setOpen(open === i.id ? null : i.id)} style={{ cursor: 'pointer' }}>
                      <td className="mono muted nw">{clock(i.detected_at)}</td>
                      <td>{i.name}</td>
                      <td className="mono">{i.info.version || '-'}</td>
                      <td>{v ? <span className={`pill ${VERDICT[v] || 'info'}`}>{v}</span> : <span className="muted">-</span>}</td>
                      <td><span className={`pill flat ${tone}`}>{label}</span></td>
                      <td onClick={(ev) => ev.stopPropagation()}>
                        {i.status !== 'analyzing' && <Button size="sm" tone="danger" onClick={() => setRemoving(i)}>Remove</Button>}
                      </td>
                    </tr>
                    {open === i.id && <tr><td colSpan="6" style={{ background: 'var(--inset)' }}><Detail i={i} /></td></tr>}
                  </Fragment>
                )
              })}
              {data && items.length === 0 && <tr><td colSpan="6" className="empty">Nothing downloaded since the monitor started. Save a program into {data.watching[0] || 'your Downloads folder'} to try it.</td></tr>}
            </tbody>
          </table>
        </div>
      </div>

      <CheckServices />

      {removing && (
        <Confirm
          danger
          busy={busy}
          title={`Remove ${removing.name}?`}
          body="The file is deleted from your folder (or from isolation) and the entry disappears from this list. This cannot be undone."
          confirmLabel="Remove"
          onConfirm={removeEntry}
          onCancel={() => setRemoving(null)}
        />
      )}

      {ask && (
        <Confirm
          danger={!ask.allow}
          busy={busy}
          title={ask.allow ? `Allow ${ask.item.name}?` : `Remove ${ask.item.name}?`}
          body={ask.allow ? 'The file will be moved back to where you downloaded it. Only do this if you trust it.' : 'The file will be deleted completely and cannot be recovered.'}
          confirmLabel={ask.allow ? 'Allow' : 'Remove'}
          onConfirm={decide}
          onCancel={() => setAsk(null)}
        />
      )}
    </>
  )
}

function Detail({ i }) {
  const v = i.verdict
  const rows = [
    ['SHA-256', i.info.sha256], ['Size', `${(i.info.size / 1048576).toFixed(2)} MB`], ['Product', i.info.product || '-'],
    ['Publisher', i.info.company || '-'], ['Signature', `${i.info.signature_status}${i.info.signer ? ` (${i.info.signer})` : ''}`],
    ['Location', i.original_path],
  ]
  const toast = useToast()
  const copy = async (text, what) => toast((await copyText(text)) ? `${what} copied` : 'Copy was blocked by the browser', 'ok')
  return (
    <div style={{ display: 'grid', gap: 12, padding: '6px 2px' }}>
      <div className="toolbar">
        <Button size="sm" icon="fileText" onClick={() => copy(rows.map(([k, val]) => `${k}: ${val}`).join('\n') + (v ? `\nVerdict: ${v.verdict} - ${v.summary}` : ''), 'Details')}>Copy details</Button>
        <Button size="sm" icon="fileText" onClick={() => copy(i.info.sha256, 'SHA-256')}>Copy SHA-256</Button>
        <Button size="sm" icon="fileText" onClick={() => copy(JSON.stringify(i, null, 2), 'JSON')}>Copy as JSON</Button>
      </div>
      <dl className="kv">
        {rows.map(([k, val]) => (
          <div key={k} style={{ display: 'flex', justifyContent: 'space-between', gap: 12 }}>
            <dt>{k}</dt><dd className="mono" style={{ textAlign: 'right', wordBreak: 'break-all' }}>{val}</dd>
          </div>
        ))}
      </dl>
      {v && (
        <>
          <div>{v.summary}</div>
          {v.vt?.known && (
            <div className="hint">
              VirusTotal: {v.vt.malicious} malicious · {v.vt.suspicious} suspicious · {v.vt.harmless} harmless · {v.vt.undetected} undetected ·{' '}
              <a href={v.vt.link} target="_blank" rel="noreferrer">open report</a>
            </div>
          )}
          {v.cves?.length > 0 && (
            <table>
              <thead><tr><th>CVE</th><th>Score</th><th>Patch</th><th>What</th></tr></thead>
              <tbody>
                {v.cves.map((c) => (
                  <tr key={c.id}>
                    <td className="mono nw"><a href={`https://nvd.nist.gov/vuln/detail/${c.id}`} target="_blank" rel="noreferrer">{c.id}</a></td>
                    <td>{c.score} {c.severity}</td>
                    <td>{c.fixed_in ? `fixed in ${c.fixed_in}` : c.patch_available ? 'available' : 'none listed'}</td>
                    <td className="muted">{c.summary}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
          {!v.cves?.length && !v.notes?.some((n) => /NVD|CPE|product/i.test(n)) && <div className="hint"><b>No record found</b> in the NVD for this product and version.</div>}
          {v.notes?.map((n) => <div key={n} className="hint">{n}</div>)}
          <ContentReport content={v.content} />
        </>
      )}
    </div>
  )
}
