import { useCallback, useEffect, useRef, useState } from "react";
import {
  Alert,
  Box,
  Button,
  CircularProgress,
  LinearProgress,
  MenuItem,
  Paper,
  Snackbar,
  Stack,
  TextField,
  Typography,
} from "@mui/material";
import Dashboard from "./Dashboard";
import type { Session } from "./Dashboard";

const API = "http://127.0.0.1:8000/api";
const POSES = ["straight", "left", "right", "up", "smile"];
const POSE_TEXT = [
  "Look straight at the camera",
  "Turn your head slightly LEFT",
  "Turn your head slightly RIGHT",
  "Tilt your head slightly UP",
  "Smile",
];
const HOLD_MS = 1500;

type Severity = "success" | "error" | "warning" | "info";
type Notify = (msg: string, severity?: Severity) => void;
type Face = { bbox: number[]; landmarks: number[][]; score: number };
type Result = { ok: boolean; code: string; message: string; session?: Session };
type Screen = "loading" | "setup" | "login" | "dashboard";

const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

async function api<T>(path: string, body?: unknown, token?: string): Promise<T> {
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
function useCamera(notify: Notify) {
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

/* ------------------------------------------------------------------ face enrollment */
function Enroll(props: {
  username: string;
  password: string;
  notify: Notify;
  onDone: (s: Session) => void;
  onFail: () => void;
}) {
  const { username, password, notify, onDone, onFail } = props;
  const { videoRef, grab } = useCamera(notify);
  const overlay = useRef<HTMLCanvasElement>(null);
  const step = useRef(0);
  const hold = useRef<number | null>(null);
  const pause = useRef(0);
  const busy = useRef(false);
  const finished = useRef(false);
  const samples = useRef<{ pose: string; image: string }[]>([]);
  const [stepUi, setStepUi] = useState(0);
  const [info, setInfo] = useState("Starting camera...");

  useEffect(() => {
    const finish = async () => {
      finished.current = true;
      setInfo("Saving your face profile...");
      try {
        const r = await api<Result>("/enroll", { username, password, samples: samples.current });
        if (r.ok && r.session) {
          notify(r.message, "success");
          onDone(r.session);
        } else {
          notify(r.message, "error");
          onFail();
        }
      } catch {
        notify("Enrollment failed. Is the security engine running?", "error");
        onFail();
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
  }, [grab, username, password, notify, onDone, onFail]);

  return (
    <Stack spacing={2} sx={{ alignItems: "center" }}>
      <Typography variant="h6">
        [{Math.min(stepUi + 1, POSES.length)}/{POSES.length}] {POSE_TEXT[Math.min(stepUi, POSES.length - 1)]}
      </Typography>
      <Box
        sx={{
          position: "relative",
          width: 560,
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
      <LinearProgress variant="determinate" value={(stepUi / POSES.length) * 100} sx={{ width: 560, maxWidth: "100%" }} />
      <Typography color="text.secondary">{info}</Typography>
    </Stack>
  );
}

/* ------------------------------------------------------------------ first-time setup */
function Setup({ notify, onDone }: { notify: Notify; onDone: (s: Session) => void }) {
  const [name, setName] = useState("");
  const [pw, setPw] = useState("");
  const [pw2, setPw2] = useState("");
  const [scanning, setScanning] = useState(false);
  const back = useCallback(() => setScanning(false), []);

  const next = () => {
    if (!/^[a-zA-Z0-9_-]{2,32}$/.test(name)) return notify("Name: 2-32 letters, numbers, - or _", "warning");
    if (pw.length < 4) return notify("Password must be at least 4 characters", "warning");
    if (pw !== pw2) return notify("Passwords do not match", "warning");
    setScanning(true);
  };

  if (scanning) return <Enroll username={name} password={pw} notify={notify} onDone={onDone} onFail={back} />;
  return (
    <Paper sx={{ p: 4, width: 360 }}>
      <Stack spacing={2}>
        <Typography variant="h5">Create your account</Typography>
        <TextField label="Name" value={name} onChange={(e) => setName(e.target.value)} autoFocus />
        <TextField label="Password / PIN" type="password" value={pw} onChange={(e) => setPw(e.target.value)} />
        <TextField label="Confirm password" type="password" value={pw2} onChange={(e) => setPw2(e.target.value)} />
        <Button variant="contained" onClick={next}>
          Next: scan my face
        </Button>
      </Stack>
    </Paper>
  );
}

/* ------------------------------------------------------------------ login (camera hidden) */
function Login({ users, notify, onSuccess }: { users: string[]; notify: Notify; onSuccess: (s: Session) => void }) {
  const { videoRef, grab } = useCamera(notify);
  const [user, setUser] = useState(users[0] ?? "");
  const [pw, setPw] = useState("");
  const [busy, setBusy] = useState(false);

  const unlock = async () => {
    if (!pw) return notify("Enter your password", "warning");
    setBusy(true);
    try {
      const images: string[] = [];
      for (let i = 0; i < 3; i++) {
        const f = grab();
        if (f) images.push(f);
        await sleep(250);
      }
      if (!images.length) return notify("Camera is still starting, try again", "warning");
      const r = await api<Result>("/login", { username: user, password: pw, images });
      if (r.ok && r.session) {
        notify(r.message, "success");
        onSuccess(r.session);
      } else {
        notify(r.message, r.code === "no_face" || r.code === "locked" ? "warning" : "error");
        setPw("");
      }
    } catch {
      notify("Security engine not reachable", "error");
    } finally {
      setBusy(false);
    }
  };

  return (
    <Paper sx={{ p: 4, width: 360 }}>
      {/* camera runs here, invisible to the user */}
      <video
        ref={videoRef}
        muted
        playsInline
        style={{ position: "absolute", width: 1, height: 1, opacity: 0, pointerEvents: "none" }}
      />
      <Stack spacing={2}>
        <Typography variant="h5">Welcome back</Typography>
        <TextField select label="User" value={user} onChange={(e) => setUser(e.target.value)}>
          {users.map((u) => (
            <MenuItem key={u} value={u}>
              {u}
            </MenuItem>
          ))}
        </TextField>
        <TextField
          label="Password / PIN"
          type="password"
          value={pw}
          autoFocus
          onChange={(e) => setPw(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && !busy && void unlock()}
        />
        <Button variant="contained" disabled={busy} onClick={() => void unlock()}>
          Unlock
        </Button>
        {busy && <LinearProgress />}
      </Stack>
    </Paper>
  );
}

/* ------------------------------------------------------------------ app */
export default function App() {
  const [screen, setScreen] = useState<Screen>("loading");
  const [users, setUsers] = useState<string[]>([]);
  const [session, setSession] = useState<Session | null>(null);
  const [snack, setSnack] = useState<{ open: boolean; msg: string; severity: Severity }>({
    open: false,
    msg: "",
    severity: "info",
  });

  const notify = useCallback<Notify>((msg, severity = "info") => setSnack({ open: true, msg, severity }), []);

  const refresh = useCallback(async () => {
    for (let i = 0; i < 120; i++) {
      try {
        const s = await api<{ enrolled: boolean; users: string[] }>("/status");
        setUsers(s.users);
        setScreen(s.enrolled ? "login" : "setup");
        return;
      } catch {
        await sleep(1000); // backend still starting / downloading models
      }
    }
    notify("Security engine did not start", "error");
  }, [notify]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const enter = useCallback((s: Session) => {
    setSession(s);
    setScreen("dashboard");
  }, []);

  const logout = () => {
    setSession(null);
    setScreen("loading");
    void refresh();
  };

  const token = session?.token;
  const loadLogs = useCallback(
    () => api<{ lines: string[] }>("/logs?n=12", undefined, token).then((r) => r.lines),
    [token],
  );

  return (
    <Box sx={{ minHeight: "100vh", display: "grid", placeItems: "center", p: 2 }}>
      {screen === "loading" && (
        <Stack spacing={2} sx={{ alignItems: "center" }}>
          <CircularProgress />
          <Typography color="text.secondary">Starting security engine...</Typography>
        </Stack>
      )}
      {screen === "setup" && <Setup notify={notify} onDone={enter} />}
      {screen === "login" && <Login users={users} notify={notify} onSuccess={enter} />}
      {screen === "dashboard" && session && <Dashboard session={session} loadLogs={loadLogs} onLogout={logout} />}

      <Snackbar
        open={snack.open}
        autoHideDuration={4500}
        onClose={(_, reason) => reason !== "clickaway" && setSnack((s) => ({ ...s, open: false }))}
        anchorOrigin={{ vertical: "bottom", horizontal: "left" }}
      >
        <Alert severity={snack.severity} variant="filled" onClose={() => setSnack((s) => ({ ...s, open: false }))}>
          {snack.msg}
        </Alert>
      </Snackbar>
    </Box>
  );
}
