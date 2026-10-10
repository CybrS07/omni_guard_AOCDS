import { useEffect, useState } from "react";
import { Button, Chip, Divider, List, ListItem, ListItemText, Paper, Stack, Typography } from "@mui/material";

export type Session = { user: string; role: string; score: number; token: string };

export default function Dashboard(props: {
  session: Session;
  loadLogs: () => Promise<string[]>;
  onLogout: () => void;
}) {
  const { session, loadLogs, onLogout } = props;
  const [lines, setLines] = useState<string[]>([]);

  useEffect(() => {
    loadLogs()
      .then(setLines)
      .catch(() => setLines([]));
  }, [loadLogs]);

  return (
    <Paper sx={{ p: 4, width: 620, maxWidth: "100%" }}>
      <Stack spacing={2}>
        <Stack direction="row" sx={{ justifyContent: "space-between", alignItems: "center" }}>
          <Typography variant="h4">Dashboard</Typography>
          <Button variant="outlined" color="inherit" onClick={onLogout}>
            Log out
          </Button>
        </Stack>
        <Stack direction="row" spacing={1} sx={{ alignItems: "center" }}>
          <Typography variant="h6">{session.user}</Typography>
          <Chip label={session.role} color={session.role === "admin" ? "success" : "default"} size="small" />
          <Chip label={`face match ${session.score}%`} size="small" variant="outlined" />
        </Stack>
        <Divider />
        <Typography variant="subtitle1">Recent security events</Typography>
        <List dense sx={{ fontFamily: "monospace" }}>
          {lines.length === 0 && <ListItem>No events yet</ListItem>}
          {[...lines].reverse().map((l, i) => (
            <ListItem key={i} disableGutters>
              <ListItemText primary={l} slotProps={{ primary: { sx: { fontSize: 13, fontFamily: "monospace" } } }} />
            </ListItem>
          ))}
        </List>
      </Stack>
    </Paper>
  );
}
