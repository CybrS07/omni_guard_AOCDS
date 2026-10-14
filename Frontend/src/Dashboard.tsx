import { useEffect, useState } from "react";
import { Box, Button, Chip, Divider, List, ListItem, ListItemText, Paper, Stack, Tab, Tabs, Typography } from "@mui/material";
import Settings from "./settings";
import type { Notify, Session } from "./shared";

type Level = "info" | "success" | "warning" | "error";
type View = "overview" | "settings";

// ---- SIMULATED data (dummy for now - replace with real agents later) ----
const POOL: [string, Level][] = [
  ["Face verification passed", "success"],
  ["Port scan blocked from 10.0.4.17", "warning"],
  ["Firewall rule set updated", "info"],
  ["Malware signature database refreshed", "info"],
  ["Suspicious login attempt blocked", "error"],
  ["Agent heartbeat OK", "success"],
  ["Unknown device joined the network", "warning"],
  ["Encrypted backup completed", "success"],
];

function Stat({ label, value, color }: { label: string; value: string | number; color?: string }) {
  return (
    <Paper sx={{ p: 2 }}>
      <Typography variant="body2" color="text.secondary">
        {label}
      </Typography>
      <Typography variant="h4" sx={{ color }}>
        {value}
      </Typography>
    </Paper>
  );
}

function Overview({ loadLogs }: { loadLogs: () => Promise<string[]> }) {
  const [series, setSeries] = useState<number[]>(() => Array.from({ length: 40 }, () => 40 + Math.random() * 30));
  const [stats, setStats] = useState({ scans: 128, threats: 7, sessions: 2, health: 98 });
  const [feed, setFeed] = useState<{ t: string; msg: string; level: Level }[]>([]);
  const [lines, setLines] = useState<string[]>([]);

  useEffect(() => {
    loadLogs()
      .then(setLines)
      .catch(() => setLines([]));
  }, [loadLogs]);

  useEffect(() => {
    const a = setInterval(() => {
      setSeries((s) => [...s.slice(1), Math.min(95, Math.max(10, s[s.length - 1] + (Math.random() - 0.5) * 24))]);
      setStats((s) => ({
        scans: s.scans + Math.floor(Math.random() * 4),
        threats: s.threats + (Math.random() < 0.1 ? 1 : 0),
        sessions: 1 + Math.floor(Math.random() * 4),
        health: 95 + Math.floor(Math.random() * 5),
      }));
    }, 1500);
    const b = setInterval(() => {
      const [msg, level] = POOL[Math.floor(Math.random() * POOL.length)];
      setFeed((f) => [{ t: new Date().toLocaleTimeString(), msg, level }, ...f].slice(0, 8));
    }, 2500);
    return () => {
      clearInterval(a);
      clearInterval(b);
    };
  }, []);

  const points = series.map((v, i) => `${(i / (series.length - 1)) * 400},${100 - v}`).join(" ");

  return (
    <Stack spacing={2}>
      <Box sx={{ display: "grid", gap: 2, gridTemplateColumns: { xs: "1fr 1fr", md: "repeat(4, 1fr)" } }}>
        <Stat label="Scans today" value={stats.scans} />
        <Stat label="Threats blocked" value={stats.threats} color="#ff5252" />
        <Stat label="Active sessions" value={stats.sessions} />
        <Stat label="System health" value={`${stats.health}%`} color="#00e676" />
      </Box>

      <Box sx={{ display: "grid", gap: 2, gridTemplateColumns: { xs: "1fr", md: "2fr 1fr" } }}>
        <Paper sx={{ p: 2 }}>
          <Typography variant="subtitle1" gutterBottom>
            Network activity (live)
          </Typography>
          <svg viewBox="0 0 400 100" preserveAspectRatio="none" style={{ width: "100%", height: 160 }}>
            <polyline points={points} fill="none" stroke="#29b6f6" strokeWidth="2" vectorEffect="non-scaling-stroke" />
          </svg>
        </Paper>
        <Paper sx={{ p: 2 }}>
          <Typography variant="subtitle1" gutterBottom>
            Live feed
          </Typography>
          <Stack spacing={1}>
            {feed.length === 0 && <Typography color="text.secondary">Waiting for events...</Typography>}
            {feed.map((f, i) => (
              <Stack key={`${f.t}-${i}`} direction="row" spacing={1} sx={{ alignItems: "center" }}>
                <Chip size="small" color={f.level} label={f.t} />
                <Typography variant="body2">{f.msg}</Typography>
              </Stack>
            ))}
          </Stack>
        </Paper>
      </Box>

      <Paper sx={{ p: 2 }}>
        <Typography variant="subtitle1">Security events (real)</Typography>
        <List dense>
          {lines.length === 0 && <ListItem>No events yet</ListItem>}
          {[...lines].reverse().map((l, i) => (
            <ListItem key={i} disableGutters>
              <ListItemText primary={l} slotProps={{ primary: { sx: { fontSize: 13, fontFamily: "monospace" } } }} />
            </ListItem>
          ))}
        </List>
      </Paper>
    </Stack>
  );
}

export default function Dashboard(props: {
  session: Session;
  loadLogs: () => Promise<string[]>;
  onLogout: () => void;
  notify: Notify;
}) {
  const { session, loadLogs, onLogout, notify } = props;
  const [view, setView] = useState<View>("overview");

  return (
    <Box sx={{ width: "100%", maxWidth: 1100, alignSelf: "start" }}>
      <Paper sx={{ p: 2, mb: 2 }}>
        <Stack direction="row" sx={{ justifyContent: "space-between", alignItems: "center" }}>
          <Stack direction="row" spacing={2} sx={{ alignItems: "center" }}>
            <Typography variant="h5">OmniGuard</Typography>
            <Chip label="simulated data" size="small" variant="outlined" />
          </Stack>
          <Stack direction="row" spacing={1} sx={{ alignItems: "center" }}>
            <Typography>{session.user}</Typography>
            <Chip label={session.role} size="small" color={session.role === "admin" ? "success" : "default"} />
            <Button variant="outlined" color="inherit" size="small" onClick={onLogout}>
              Log out
            </Button>
          </Stack>
        </Stack>
        <Divider sx={{ my: 1 }} />
        <Tabs value={view} onChange={(_, v: View) => setView(v)}>
          <Tab value="overview" label="Dashboard" />
          <Tab value="settings" label="Settings" />
        </Tabs>
      </Paper>

      {view === "overview" ? <Overview loadLogs={loadLogs} /> : <Settings session={session} notify={notify} />}
    </Box>
  );
}
