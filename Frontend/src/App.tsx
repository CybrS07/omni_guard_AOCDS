import { useCallback, useEffect, useState } from "react";
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
import { Enroll, api, sleep, useCamera } from "./shared";
import type { Notify, Result, Sample, Session, Severity } from "./shared";

type Screen = "loading" | "setup" | "login" | "dashboard";

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

  if (scanning)
    return (
      <Enroll
        submit={(samples: Sample[]) => api<Result>("/enroll", { username: name, password: pw, samples })}
        notify={notify}
        onDone={(r) => {
          if (r.session) {
            notify(r.message, "success");
            onDone(r.session);
          }
        }}
        onFail={back}
      />
    );
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
      {screen === "dashboard" && session && <Dashboard session={session} loadLogs={loadLogs} onLogout={logout} notify={notify} />}

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
