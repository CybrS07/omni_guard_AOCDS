import { useCallback, useEffect, useState } from "react";
import {
  Button,
  Chip,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  MenuItem,
  Paper,
  Stack,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableRow,
  TextField,
  Typography,
} from "@mui/material";
import { Enroll, api } from "./shared";
import type { Notify, Result, Sample, Session, UserRow } from "./shared";

/* ---------------- change password ---------------- */
function PasswordDialog(props: { target: string; self: boolean; token: string; notify: Notify; onClose: () => void }) {
  const { target, self, token, notify, onClose } = props;
  const [current, setCurrent] = useState("");
  const [pw, setPw] = useState("");
  const [pw2, setPw2] = useState("");

  const save = async () => {
    if (pw !== pw2) return notify("Passwords do not match", "warning");
    try {
      const r = await api<Result>(
        "/users/password",
        { username: target, new_password: pw, current_password: current },
        token,
      );
      notify(r.message, r.ok ? "success" : "error");
      if (r.ok) onClose();
    } catch {
      notify("Could not update password", "error");
    }
  };

  return (
    <Dialog open onClose={onClose} fullWidth maxWidth="xs">
      <DialogTitle>Change password - {target}</DialogTitle>
      <DialogContent>
        <Stack spacing={2} sx={{ pt: 1 }}>
          {self && (
            <TextField label="Current password" type="password" value={current} onChange={(e) => setCurrent(e.target.value)} />
          )}
          <TextField label="New password" type="password" value={pw} onChange={(e) => setPw(e.target.value)} />
          <TextField label="Confirm new password" type="password" value={pw2} onChange={(e) => setPw2(e.target.value)} />
        </Stack>
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose}>Cancel</Button>
        <Button variant="contained" onClick={() => void save()}>
          Save
        </Button>
      </DialogActions>
    </Dialog>
  );
}

/* ---------------- delete user ---------------- */
function DeleteDialog(props: { target: string; token: string; notify: Notify; onClose: () => void; onDone: () => void }) {
  const { target, token, notify, onClose, onDone } = props;

  const remove = async () => {
    try {
      const r = await api<Result>("/users/delete", { username: target }, token);
      notify(r.message, r.ok ? "success" : "error");
      if (r.ok) onDone();
      onClose();
    } catch {
      notify("Could not delete user", "error");
    }
  };

  return (
    <Dialog open onClose={onClose}>
      <DialogTitle>Delete {target}?</DialogTitle>
      <DialogContent>
        <Typography>This removes the password, face data and XML record of this user. It cannot be undone.</Typography>
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose}>Cancel</Button>
        <Button color="error" variant="contained" onClick={() => void remove()}>
          Delete
        </Button>
      </DialogActions>
    </Dialog>
  );
}

/* ---------------- add user (details, then face scan) ---------------- */
function AddUserDialog(props: { token: string; notify: Notify; onClose: () => void; onAdded: () => void }) {
  const { token, notify, onClose, onAdded } = props;
  const [name, setName] = useState("");
  const [pw, setPw] = useState("");
  const [pw2, setPw2] = useState("");
  const [role, setRole] = useState("user");
  const [scanning, setScanning] = useState(false);

  const next = () => {
    if (!/^[a-zA-Z0-9_-]{2,32}$/.test(name)) return notify("Name: 2-32 letters, numbers, - or _", "warning");
    if (pw.length < 4) return notify("Password must be at least 4 characters", "warning");
    if (pw !== pw2) return notify("Passwords do not match", "warning");
    setScanning(true);
  };

  return (
    <Dialog open onClose={scanning ? undefined : onClose} fullWidth maxWidth="md">
      <DialogTitle>Add user</DialogTitle>
      <DialogContent>
        {scanning ? (
          <Enroll
            submit={(samples: Sample[]) => api<Result>("/users/add", { username: name, password: pw, role, samples }, token)}
            notify={notify}
            onDone={(r) => {
              notify(r.message, "success");
              onAdded();
              onClose();
            }}
            onFail={() => setScanning(false)}
          />
        ) : (
          <Stack spacing={2} sx={{ pt: 1, maxWidth: 360 }}>
            <TextField label="Name" value={name} onChange={(e) => setName(e.target.value)} autoFocus />
            <TextField label="Password / PIN" type="password" value={pw} onChange={(e) => setPw(e.target.value)} />
            <TextField label="Confirm password" type="password" value={pw2} onChange={(e) => setPw2(e.target.value)} />
            <TextField select label="Role" value={role} onChange={(e) => setRole(e.target.value)}>
              <MenuItem value="user">user</MenuItem>
              <MenuItem value="admin">admin</MenuItem>
            </TextField>
          </Stack>
        )}
      </DialogContent>
      {!scanning && (
        <DialogActions>
          <Button onClick={onClose}>Cancel</Button>
          <Button variant="contained" onClick={next}>
            Next: scan face
          </Button>
        </DialogActions>
      )}
    </Dialog>
  );
}

/* ---------------- settings page ---------------- */
export default function Settings({ session, notify }: { session: Session; notify: Notify }) {
  const admin = session.role === "admin";
  const [rows, setRows] = useState<UserRow[]>([]);
  const [pwFor, setPwFor] = useState<string | null>(null);
  const [delFor, setDelFor] = useState<string | null>(null);
  const [adding, setAdding] = useState(false);

  const load = useCallback(async () => {
    try {
      const r = await api<{ users: UserRow[] }>("/users", undefined, session.token);
      setRows(r.users);
    } catch {
      notify("Could not load users", "error");
    }
  }, [session.token, notify]);

  useEffect(() => {
    void load();
  }, [load]);

  const me = rows.find((r) => r.name === session.user);

  return (
    <Stack spacing={2}>
      <Paper sx={{ p: 3 }}>
        <Typography variant="h6" gutterBottom>
          My account
        </Typography>
        <Stack spacing={0.5}>
          <Typography>Name: {session.user}</Typography>
          <Typography>Role: {session.role}</Typography>
          <Typography>Created: {me?.created ?? "-"}</Typography>
          <Typography>Face variations stored: {me?.variations ?? "-"}</Typography>
          <Typography>Last face match: {session.score}%</Typography>
        </Stack>
        <Button sx={{ mt: 2 }} variant="outlined" onClick={() => setPwFor(session.user)}>
          Change my password
        </Button>
      </Paper>

      {admin && (
        <Paper sx={{ p: 3 }}>
          <Stack direction="row" sx={{ justifyContent: "space-between", alignItems: "center", mb: 1 }}>
            <Typography variant="h6">Users</Typography>
            <Button variant="contained" onClick={() => setAdding(true)}>
              Add user
            </Button>
          </Stack>
          <Table size="small">
            <TableHead>
              <TableRow>
                <TableCell>Name</TableCell>
                <TableCell>Role</TableCell>
                <TableCell>Created</TableCell>
                <TableCell>Face samples</TableCell>
                <TableCell align="right">Actions</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {rows.map((u) => (
                <TableRow key={u.name}>
                  <TableCell>
                    {u.name} {u.name === session.user && <Chip size="small" label="you" />}
                  </TableCell>
                  <TableCell>{u.role}</TableCell>
                  <TableCell>{u.created}</TableCell>
                  <TableCell>{u.variations}</TableCell>
                  <TableCell align="right">
                    <Button size="small" onClick={() => setPwFor(u.name)}>
                      Password
                    </Button>
                    <Button size="small" color="error" disabled={u.name === session.user} onClick={() => setDelFor(u.name)}>
                      Delete
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </Paper>
      )}

      {pwFor && (
        <PasswordDialog
          target={pwFor}
          self={pwFor === session.user}
          token={session.token}
          notify={notify}
          onClose={() => setPwFor(null)}
        />
      )}
      {delFor && (
        <DeleteDialog
          target={delFor}
          token={session.token}
          notify={notify}
          onClose={() => setDelFor(null)}
          onDone={() => void load()}
        />
      )}
      {adding && (
        <AddUserDialog
          token={session.token}
          notify={notify}
          onClose={() => setAdding(false)}
          onAdded={() => void load()}
        />
      )}
    </Stack>
  );
}
