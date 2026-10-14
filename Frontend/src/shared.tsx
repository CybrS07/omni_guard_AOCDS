import { useCallback, useEffect, useRef, useState } from "react";
import { Box, LinearProgress, Stack, Typography } from "@mui/material";

const API = "http://127.0.0.1:8000/api";
export const POSES = ["straight", "left", "right", "up", "smile"];
const POSE_TEXT = [
  "Look straight at the camera",
  "Turn your head slightly LEFT",
  "Turn your head slightly RIGHT",
  "Tilt your head slightly UP",
  "Smile",
];
const HOLD_MS = 1500;

export type Severity = "success" | "error" | "warning" | "info";
export type Notify = (msg: string, severity?: Severity) => void;
export type Session = { user: string; role: string; score: number; token: string };
export type Result = { ok: boolean; code: string; message: string; session?: Session };
export type UserRow = { name: string; role: string; created: string; variations: number };
export type Sample = { pose: string; image: string };
type Face = { bbox: number[]; landmarks: number[][]; score: number };

export const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

export async function api<T>(path: string, body?: unknown, token?: string): Promise<T> {
  const res = await fetch(`${API}${path}`, {
    method: body === undefined ? "GET" : "POST",
    headers: { "Content-Type": "application/json", ...(token ? { "x-token": token } : {}) },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (!res.ok) {
    const err = (await res.json().catch(() => ({}))) as { detail?: string };
    throw new Error(err.detail ?? `HTTP ${res.status}`);
  }
  return (await res.json()) as T;
}

/** Opens the webcam. `grab()` returns the current frame as a JPEG data-URL. */
export function useCamera(notify: Notify) {
  const videoRef = useRef<HTMLVideoElement>(null);
  const canvas = useRef<HTMLCanvasElement>(document.createElement("canvas"));

  useEffect(() => {
    let stream: MediaStream | null = null;
    let stopped = false;
    navigator.mediaDevices
      .getUserMedia({ video: { width: 640, height: 480 } })
      .then((s) => {
        if (stopped) {
          s.getTracks().forEach((t) => t.stop());
          return;
        }
        stream = s;
        const v = videoRef.current;
        if (v) {
          v.srcObject = s;
          v.play().catch(() => undefined);
        }
      })
      .catch(() => notify("Cannot open the camera. Check camera permission.", "error"));
    return () => {
      stopped = true;
      stream?.getTracks().forEach((t) => t.stop());
    };
  }, [notify]);

  const grab = useCallback((): string | null => {
    const v = videoRef.current;
    if (!v || !v.videoWidth) return null;
    const c = canvas.current;
    c.width = v.videoWidth;
    c.height = v.videoHeight;
    c.getContext("2d")?.drawImage(v, 0, 0);
    return c.toDataURL("image/jpeg", 0.85);
  }, []);

  return { videoRef, grab };
}

function drawOverlay(c: HTMLCanvasElement | null, face: Face | null, size?: number[]) {
  if (!c) return;
  const [w, h] = size ?? [640, 480];
  c.width = w;
  c.height = h;
  const g = c.getContext("2d");
  if (!g || !face) return;
  const [x, y, bw, bh] = face.bbox;
  g.strokeStyle = "#00e676";
  g.lineWidth = 3;
  g.strokeRect(x, y, bw, bh);
  g.fillStyle = "#ff1744";
  face.landmarks.forEach(([px, py]) => {
    g.beginPath();
    g.arc(px, py, 4, 0, Math.PI * 2);
    g.fill();
  });
}

/** Guided face scan (markers + 5 poses). Used for first setup AND adding users in Settings.
 *  `submit` sends the captured samples to whichever endpoint the caller wants. */
export function Enroll(props: {
  submit: (samples: Sample[]) => Promise<Result>;
  notify: Notify;
  onDone: (r: Result) => void;
  onFail: () => void;
}) {
  const { notify } = props;
  const cb = useRef(props);
  cb.current = props;
  const { videoRef, grab } = useCamera(notify);
  const overlay = useRef<HTMLCanvasElement>(null);
  const step = useRef(0);
  const hold = useRef<number | null>(null);
  const pause = useRef(0);
  const busy = useRef(false);
  const finished = useRef(false);
  const samples = useRef<Sample[]>([]);
  const [stepUi, setStepUi] = useState(0);
  const [info, setInfo] = useState("Starting camera...");

  useEffect(() => {
    const finish = async () => {
      finished.current = true;
      setInfo("Saving face profile...");
      try {
        const r = await cb.current.submit(samples.current);
        if (r.ok) {
          cb.current.onDone(r);
        } else {
          notify(r.message, "error");
          cb.current.onFail();
        }
      } catch {
        notify("Face enrollment failed. Is the security engine running?", "error");
        cb.current.onFail();
      }
    };

    const id = setInterval(async () => {
      if (busy.current || finished.current) return;
      const image = grab();
      if (!image) return;
      busy.current = true;
      try {
        const r = await api<{ face: Face | null; size: number[] }>("/detect", { image });
        drawOverlay(overlay.current, r.face, r.size);
        const now = Date.now();
        if (now < pause.current) {
          setInfo("Captured ✓");
        } else if (!r.face) {
          hold.current = null;
          setInfo("No face found - look at the camera");
        } else {
          hold.current ??= now;
          const left = HOLD_MS - (now - hold.current);
          setInfo(`Hold still... ${(Math.max(left, 0) / 1000).toFixed(1)}s`);
          if (left <= 0) {
            samples.current.push({ pose: POSES[step.current], image });
            step.current += 1;
            setStepUi(step.current);
            hold.current = null;
            pause.current = now + 1000;
            if (step.current >= POSES.length) await finish();
          }
        }
      } catch {
        setInfo("Waiting for the security engine...");
      } finally {
        busy.current = false;
      }
    }, 350);
    return () => clearInterval(id);
  }, [grab, notify]);

  return (
    <Stack spacing={2} sx={{ alignItems: "center" }}>
      <Typography variant="h6">
        [{Math.min(stepUi + 1, POSES.length)}/{POSES.length}] {POSE_TEXT[Math.min(stepUi, POSES.length - 1)]}
      </Typography>
      <Box
        sx={{
          position: "relative",
          width: 520,
          maxWidth: "100%",
          transform: "scaleX(-1)",
          borderRadius: 2,
          overflow: "hidden",
          bgcolor: "black",
        }}
      >
        <video ref={videoRef} muted playsInline style={{ width: "100%", display: "block" }} />
        <canvas ref={overlay} style={{ position: "absolute", inset: 0, width: "100%", height: "100%" }} />
      </Box>
      <LinearProgress variant="determinate" value={(stepUi / POSES.length) * 100} sx={{ width: 520, maxWidth: "100%" }} />
      <Typography color="text.secondary">{info}</Typography>
    </Stack>
  );
}
