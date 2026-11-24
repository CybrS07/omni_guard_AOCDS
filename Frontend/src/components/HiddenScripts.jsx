import { Accordion, Badge } from '@mantine/core'
import Button from './Button.jsx'
import { useToast } from './Feedback.jsx'
import { copyText } from '../export.js'

// Plain names for what was hidden.
const KIND = {
  script: 'Script',
  text: 'Text',
  pe: 'Windows program',
  zip: 'ZIP archive',
  elf: 'Linux program',
  pdf: 'PDF',
  binary: 'Binary data',
}

// Turn a byte count into KB / MB.
function bytes(n) {
  if (n >= 1048576) return `${(n / 1048576).toFixed(1)} MB`
  if (n >= 1024) return `${(n / 1024).toFixed(1)} KB`
  return `${n} B`
}

/** A box of code / text. */
function Code({ text }) {
  return (
    <pre
      className="mono"
      style={{
        margin: 0,
        padding: 12,
        borderRadius: 10,
        border: '1px solid var(--line)',
        background: 'var(--input-bg)',
        maxHeight: 260,
        overflow: 'auto',
        whiteSpace: 'pre-wrap',
        wordBreak: 'break-all',
      }}
    >
      {text}
    </pre>
  )
}

/** A short list such as "Web addresses found". Shows nothing when the list is empty. */
function Found({ title, items }) {
  if (!items || items.length === 0) return null
  return (
    <div>
      <b>{title}</b>
      <ul style={{ margin: '4px 0 0', paddingLeft: 18 }}>
        {items.map((x) => (
          <li key={x} className="mono" style={{ wordBreak: 'break-all' }}>{x}</li>
        ))}
      </ul>
    </div>
  )
}

/**
 * Everything that was hidden inside a file (pixels, after the end of the file, comments, archives ...).
 * For a script that is scrambled on purpose (obfuscated) we show:
 *   1. what was hidden (as found)
 *   2. every layer that was peeled off
 *   3. the final readable script
 *   4. web addresses, IP addresses, file paths and commands inside it
 */
export default function HiddenScripts({ hidden }) {
  const toast = useToast()

  const copy = async (text, what) => {
    const ok = await copyText(text)
    toast(ok ? `${what} copied` : 'Copy was blocked by the browser', ok ? 'ok' : 'err')
  }

  return (
    <div style={{ display: 'grid', gap: 14 }}>
      {hidden.map((h, i) => {
        const d = h.deobf
        return (
          <div key={i}>
            <div className="toolbar" style={{ marginBottom: 6 }}>
              <b>Hidden {KIND[h.kind] || h.kind}</b>
              {d && <Badge color="red">scrambled on purpose</Badge>}
              <span className="hint">
                {h.where} · {bytes(h.length)}
                {h.offset ? ` · at byte ${h.offset}` : ''}
              </span>
              <Button size="sm" icon="fileText" onClick={() => copy(h.text, 'Hidden data')}>Copy</Button>
            </div>

            {/* the hidden data exactly as found */}
            <Code text={h.text} />

            {['pe', 'zip', 'binary', 'elf', 'pdf'].includes(h.kind) && (
              <div className="hint">Binary data is shown as hex (first bytes). It is not saved or run.</div>
            )}

            {/* the readable version of a scrambled script */}
            {d && (
              <div style={{ display: 'grid', gap: 10, marginTop: 10 }}>
                <div className="toolbar">
                  {d.techniques.map((t) => (
                    <Badge key={t} variant="light" color="orange">{t}</Badge>
                  ))}
                </div>

                {d.layers.length > 0 && (
                  <Accordion variant="contained">
                    {d.layers.map((layer, n) => (
                      <Accordion.Item key={n} value={String(n)}>
                        <Accordion.Control>Layer {n + 1}: {layer.method}</Accordion.Control>
                        <Accordion.Panel><Code text={layer.text} /></Accordion.Panel>
                      </Accordion.Item>
                    ))}
                  </Accordion>
                )}

                <div>
                  <div className="toolbar" style={{ marginBottom: 6 }}>
                    <b>Readable script (after removing the scrambling)</b>
                    <Button size="sm" icon="fileText" onClick={() => copy(d.final, 'Readable script')}>Copy</Button>
                  </div>
                  <Code text={d.final} />
                </div>

                <Found title="Web addresses" items={d.urls} />
                <Found title="IP addresses" items={d.ips} />
                <Found title="File paths" items={d.paths} />
                <Found title="Commands" items={d.commands} />
                <div className="hint">Nothing was run. The layers were opened with plain text decoders only.</div>
              </div>
            )}
          </div>
        )
      })}
    </div>
  )
}
