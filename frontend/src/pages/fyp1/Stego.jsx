import { useState } from 'react'
import FileDrop from '../../components/FileDrop.jsx'
import Table from '../../components/Table.jsx'

export default function Stego() {
  const [results, setResults] = useState([])
  // TODO: upload to /api/stego/scan
  const scan = (f) => setResults((r) => [{ file: f.name, type: f.type || 'unknown', verdict: 'pending' }, ...r])
  return (
    <>
      <h1>Steganography</h1>
      <FileDrop onFile={scan} accept="image/*,audio/*,video/*" label="Drop an image, audio or video file" />
      <h2>Results</h2>
      <Table columns={[{ key: 'file', label: 'File' }, { key: 'type', label: 'Type' }, { key: 'verdict', label: 'Verdict' }]} rows={results} />
    </>
  )
}
