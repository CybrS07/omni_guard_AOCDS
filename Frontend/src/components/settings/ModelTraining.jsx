import { useEffect, useRef, useState } from 'react'
import Button from '../Button.jsx'
import { useToast } from '../Feedback.jsx'
import Icon from '../Icon.jsx'
import { useScan } from '../../scan/ScanGate.jsx'
import { scanApi } from '../../scan/scanApi.js'

/**
 * Local AI model: shows which weights are live, trains new ones on this computer (about 30 seconds, no internet)
 * and swaps them in without a restart. "Go back" deletes the local weights and uses the model shipped with the app.
 */
export default function ModelTraining() {
  const { token } = useScan()
  const toast = useToast()
  const [info, setInfo] = useState(null)
  const timer = useRef(null)

  const load = () => scanApi('/model/status').then(setInfo).catch(() => setInfo(null))

  useEffect(() => {
    load()
    return () => clearInterval(timer.current)
  }, [])

  // while a job runs, look at its progress every 2 seconds
  useEffect(() => {
    clearInterval(timer.current)
    if (info?.job?.running) timer.current = setInterval(load, 2000)
    return () => clearInterval(timer.current)
  }, [info?.job?.running])

  const train = async () => {
    try {
      setInfo(await scanApi('/model/train', { method: 'POST', token, body: {} }))
      toast('Training started')
    } catch (e) {
      toast(e.message, 'err')
    }
  }

  const reset = async () => {
    try {
      setInfo(await scanApi('/model/reset', { method: 'POST', token }))
      toast('Using the model shipped with the app')
    } catch (e) {
      toast(e.message, 'err')
    }
  }

  const isAdmin = !!token
  const job = info?.job
  const report = info?.report || {}
  return (
    <div className="panel" id="model">
      <div className="panel-head">
        <h2><Icon name="refresh" size={20} /> Script AI model</h2>
        <span className="hint">{info ? `${info.live} · ${info.size_kb} KB` : 'service not reachable'}</span>
      </div>
      <p className="hint" style={{ margin: '0 0 10px' }}>
        Train the model on this computer (generated samples plus harmless scripts found here). The new weights replace the old ones at once.
        {report.trained_at ? ` Last training: ${new Date(report.trained_at * 1000).toLocaleString()}, ${report.test_accuracy}% test accuracy, ${report.false_alarms} false alarms.` : ''}
      </p>
      {job?.running && <pre className="hint" style={{ maxHeight: 120, overflow: 'auto', margin: '0 0 10px' }}>{job.lines.join('\n') || 'Starting...'}</pre>}
      <div className="toolbar" style={{ justifyContent: 'space-between' }}>
        <span className="hint">{job?.message}{job?.mode ? ` (${job.mode})` : ''}</span>
        <span style={{ display: 'flex', gap: 8 }}>
          <Button disabled={!isAdmin || info?.live?.startsWith('shipped')} onClick={reset}>Go back to shipped model</Button>
          <Button variant="primary" busy={!!job?.running} disabled={!isAdmin} onClick={train}>Train now</Button>
        </span>
      </div>
    </div>
  )
}
