const { app, BrowserWindow, Menu } = require("electron");
const { spawn } = require("child_process");
const path = require("path");

const dev = process.argv.includes("--dev");
let backend = null;

// starts the Python backend automatically (set NO_BACKEND=1 to run it yourself)
function startBackend() {
  if (process.env.NO_BACKEND) return;
  const cwd = path.join(__dirname, "..", "..", "Backend", "Python");
  backend = spawn("uv", ["run", "uvicorn", "API.server:app", "--host", "127.0.0.1", "--port", "8000"], {
    cwd,
    stdio: "inherit",
  });
  backend.on("error", (e) => console.error("Backend failed to start:", e.message));
}

function createWindow() {
  Menu.setApplicationMenu(null);
  const win = new BrowserWindow({ width: 1000, height: 720, autoHideMenuBar: true });
  if (dev) win.loadURL("http://localhost:5173");
  else win.loadFile(path.join(__dirname, "..", "dist", "index.html"));
}

app.whenReady().then(() => {
  startBackend();
  createWindow();
});
app.on("window-all-closed", () => app.quit());
app.on("before-quit", () => backend && backend.kill());
