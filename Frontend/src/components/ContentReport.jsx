import { Accordion, Badge } from '@mantine/core'
import HiddenScripts from './HiddenScripts.jsx'

const SEV = { critical: 'critical', high: 'high', medium: 'medium', low: 'low', info: 'info' }

/** exiftool-style list of every metadata field, grouped (EXIF, XMP, PNG, PDF ...). */
export function MetadataTable({ metadata }) {
  if (!metadata || !metadata.fields) return null
  const groups = Object.entries(metadata.groups || {})
  return (
    <Accordion variant="contained">
      <Accordion.Item value="meta">
        <Accordion.Control>Metadata · {metadata.fields} fields <span className="hint">({metadata.tool})</span></Accordion.Control>
        <Accordion.Panel>
          {groups.map(([g, tags]) => (
            <div key={g} style={{ marginBottom: 10 }}>
              <b>{g}</b>
              <table>
                <tbody>
                  {Object.entries(tags).map(([k, val]) => (
                    <tr key={k}>
                      <td className="nw muted" style={{ width: 200 }}>{k}</td>
                      <td className="mono" style={{ wordBreak: 'break-all' }}>{String(val).slice(0, 400)}{String(val).length > 400 ? ' …' : ''}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ))}
          {!groups.length && <div className="hint">No metadata fields.</div>}
        </Accordion.Panel>
      </Accordion.Item>
    </Accordion>
  )
}

/** What the content check found in a file: findings, the hidden data itself (decoded), metadata and the AI score. */
export default function ContentReport({ content }) {
  if (!content) return null
  const { findings = [], hidden = [], metadata, pe_ai: ai, yara } = content
  if (!findings.length && !hidden.length && !metadata?.fields && !ai && !yara) return null
  const yaraHits = [...(yara?.file_matches || []), ...(yara?.hidden_matches || [])]
  return (
    <div style={{ display: 'grid', gap: 12 }}>
      <div className="toolbar">
        <b>Content check</b>
        <span className={`pill flat ${content.verdict === 'malicious' ? 'critical' : content.verdict === 'suspicious' ? 'warn' : 'ok'}`}>{content.verdict}</span>
        {yara && (
          <Badge color={!yara.ready ? 'gray' : yaraHits.length ? 'red' : 'green'} variant="light">
            {!yara.ready ? 'YARA not ready' : yaraHits.length ? `YARA matched: ${yaraHits.join(', ')}` : `YARA: ${yara.rules} rules, no match`}
          </Badge>
        )}
        {ai && <Badge color={ai.probability >= 0.9 ? 'red' : ai.probability >= 0.7 ? 'orange' : 'gray'} variant="light">AI structure score {ai.probability.toFixed(2)}</Badge>}
      </div>
      {findings.length > 0 && (
        <table>
          <thead><tr><th>Severity</th><th>What was found</th><th>Details</th></tr></thead>
          <tbody>
            {findings.map((f, i) => (
              <tr key={i}>
                <td><span className={`pill flat ${SEV[f.severity] || 'info'}`}>{f.severity}</span></td>
                <td>{f.title}</td>
                <td className="muted" style={{ wordBreak: 'break-word' }}>{f.detail}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {hidden.length > 0 && (
        <>
          <b>Hidden data (shown as found, never run)</b>
          <HiddenScripts hidden={hidden} />
        </>
      )}
      <MetadataTable metadata={metadata} />
    </div>
  )
}
