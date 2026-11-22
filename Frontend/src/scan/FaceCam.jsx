import { useCallback, useEffect, useRef, useState } from 'react'
import { scanApi } from './scanApi.js'

const DETECT_WIDTH = 320 // small frames keep the live preview light
const DETECT_EVERY_MS = 450

/**
 * Webcam + live face markers. The face is found by the Python service (/detect), the box and
 * the 5 landmarks are drawn on an overlay canvas. `grab()` returns a JPEG data-URL.
 */
export function useFaceCam(enabled = true) {
  const videoRef = useRef(null)
  const overlayRef = useRef(null)
  const work = useRef(null)
  const [cam, setCam] = useState({ status: 'starting', error: '' })
  const [face, setFace] = useState(null) // {bbox, landmarks, score, size}

  const grab = useCallback((maxWidth = 640, quality = 0.85) => {
    const v = videoRef.current
    if (!v || !v.videoWidth) return null
    const scale = Math.min(1, maxWidth / v.videoWidth)
    const c = (work.current ||= document.createElement('canvas'))
    c.width = Math.round(v.videoWidth * scale)
    c.height = Math.round(v.videoHeight * scale)
    c.getContext('2d').drawImage(v, 0, 0, c.width, c.height)
    return c.toDataURL('image/jpeg', quality)
  }, [])

  // open / close the camera
  useEffect(() => {
    if (!enabled) return undefined
    let dead = false
    let stream
    setCam({ status: 'starting', error: '' })
    if (!navigator.mediaDevices?.getUserMedia) {
      setCam({ status: 'error', error: 'This browser cannot access the camera here.' })
      return undefined
    }
    navigator.mediaDevices
      .getUserMedia({ video: { width: { ideal: 640 }, height: { ideal: 480 }, facingMode: 'user' }, audio: false })
      .then((s) => {
        if (dead) return s.getTracks().forEach((t) => t.stop())
        stream = s
        const v = videoRef.current
        v.srcObject = s
        v.onloadedmetadata = () => {
          v.play?.()
          v.parentElement.style.aspectRatio = `${v.videoWidth} / ${v.videoHeight}`
          setCam({ status: 'ready', error: '' })
        }
      })
      .catch((e) => {
        const msg = e?.name === 'NotAllowedError' ? 'Camera permission was denied. Allow it in the browser and retry.' : e?.name === 'NotFoundError' ? 'No camera found.' : 'Could not start the camera.'
        if (!dead) setCam({ status: 'error', error: msg })
      })
    return () => {
      dead = true
      stream?.getTracks().forEach((t) => t.stop())
    }
  }, [enabled])

  // live detection loop
  useEffect(() => {
    if (cam.status !== 'ready') return undefined
    let alive = true
    let timer
    const tick = async () => {
      const image = grab(DETECT_WIDTH, 0.6)
      if (image) {
        try {
          const r = await scanApi('/detect', { method: 'POST', body: { image } })
          if (alive) {
            const f = r.face ? { ...r.face, size: r.size } : null
            setFace(f)
            paint(overlayRef.current, f)
          }
        } catch {
          if (alive) {
            setFace(null)
            paint(overlayRef.current, null)
          }
        }
      }
      if (alive) timer = setTimeout(tick, DETECT_EVERY_MS)
    }
    tick()
    return () => {
      alive = false
      clearTimeout(timer)
    }
  }, [cam.status, grab])

  // "usable" = a face is found and fills a reasonable part of the frame
  const faceOk = !!face && face.bbox[2] / face.size[0] > 0.18
  return { videoRef, overlayRef, cam, face, faceOk, grab }
}

function paint(canvas, face) {
  if (!canvas) return
  const w = canvas.clientWidth
  const h = canvas.clientHeight
  if (canvas.width !== w) canvas.width = w
  if (canvas.height !== h) canvas.height = h
  const ctx = canvas.getContext('2d')
  ctx.clearRect(0, 0, w, h)
  if (!face) return
  const sx = w / face.size[0]
  const sy = h / face.size[1]
  const [x, y, bw, bh] = face.bbox
  const color = getComputedStyle(canvas).getPropertyValue('--accent').trim() || 'currentColor'
  ctx.strokeStyle = color
  ctx.fillStyle = color
  ctx.lineWidth = 2
  // corner brackets
  const L = Math.min(bw, bh) * sx * 0.22
  const [x0, y0, x1, y1] = [x * sx, y * sy, (x + bw) * sx, (y + bh) * sy]
  ctx.beginPath()
  for (const [cx, cy, dx, dy] of [[x0, y0, 1, 1], [x1, y0, -1, 1], [x0, y1, 1, -1], [x1, y1, -1, -1]]) {
    ctx.moveTo(cx, cy + dy * L)
    ctx.lineTo(cx, cy)
    ctx.lineTo(cx + dx * L, cy)
  }
  ctx.stroke()
  for (const [lx, ly] of face.landmarks) {
    ctx.beginPath()
    ctx.arc(lx * sx, ly * sy, 3, 0, Math.PI * 2)
    ctx.fill()
  }
}

/** The camera picture with the overlay. Mirrored like a mirror; captured frames are not. */
export function CamStage({ cam, videoRef, overlayRef, ok }) {
  return (
    <div className={`cam ${ok ? 'ok' : ''}`} style={{ aspectRatio: '4 / 3' }}>
      <div className="cam-mirror">
        <video ref={videoRef} muted playsInline />
        <canvas ref={overlayRef} />
      </div>
      {cam.status === 'starting' && <div className="cam-msg">Starting camera…</div>}
      {cam.status === 'error' && <div className="cam-msg err">{cam.error}</div>}
    </div>
  )
}
