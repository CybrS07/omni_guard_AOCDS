import { useEffect, useRef, useState } from 'react'

// Opens the webcam for face enroll/verify. Attach videoRef to a <video autoPlay playsInline>.
export default function useCamera() {
  const videoRef = useRef(null)
  const [error, setError] = useState(null)

  useEffect(() => {
    let stream
    navigator.mediaDevices
      .getUserMedia({ video: true })
      .then((s) => {
        stream = s
        if (videoRef.current) videoRef.current.srcObject = s
      })
      .catch((e) => setError(e.message))
    return () => stream?.getTracks().forEach((t) => t.stop())
  }, [])

  return { videoRef, error }
}
