import { copyText, saveFile, stamp, toCsv } from '../export.js'
import Button from './Button.jsx'
import { useToast } from './Feedback.jsx'

/**
 * Copy / save buttons for a list of records.
 *   name  - file name prefix            rows - flat objects for CSV
 *   full  - (optional) the complete objects, used for JSON (CVE lists etc.)
 */
export default function ExportBar({ name, rows, full }) {
  const toast = useToast()
  const json = () => JSON.stringify(full || rows, null, 2)
  const empty = !rows.length
  return (
    <div className="toolbar">
      <Button size="sm" icon="fileText" disabled={empty} onClick={async () => toast((await copyText(json())) ? 'Copied as JSON' : 'Copy was blocked by the browser', 'ok')}>Copy</Button>
      <Button size="sm" icon="download" disabled={empty} onClick={() => saveFile(`${name}-${stamp()}.json`, json(), 'application/json')}>JSON</Button>
      <Button size="sm" icon="download" disabled={empty} onClick={() => saveFile(`${name}-${stamp()}.csv`, toCsv(rows), 'text/csv')}>CSV</Button>
    </div>
  )
}
