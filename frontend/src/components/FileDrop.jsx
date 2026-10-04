import { useRef, useState } from 'react'

// Drag a file here (or click) -> onFile(file)
export default function FileDrop({ onFile, accept, label = 'Drop a file to scan or click to choose' }) {
  const input = useRef(null)
  const [over, setOver] = useState(false)
  const pick = (f) => f && onFile(f)

  return (
    <div
      className={`drop ${over ? 'over' : ''}`}
      onClick={() => input.current.click()}
      onDragOver={(e) => { e.preventDefault(); setOver(true) }}
      onDragLeave={() => setOver(false)}
      onDrop={(e) => { e.preventDefault(); setOver(false); pick(e.dataTransfer.files[0]) }}
    >
      {label}
      <input ref={input} type="file" accept={accept} hidden onChange={(e) => pick(e.target.files[0])} />
    </div>
  )
}
