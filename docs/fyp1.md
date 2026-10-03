# FYP-1: Foundation and Passive Detection

## Scope
- **Security:** face scan login (one-time enroll), PIN fallback, encrypted vault, access gate.
- **Main AI agent:** supervises all modules, correlates findings, sends email and voice alerts.
- **Module 1:** virus / malware / ransomware detection (hash, YARA, PE features, ONNX, canary files).
- **Module 3:** steganography detection (image, audio, video).
- **Frontend:** login, dashboard, malware page, stego page, settings.

## Folders
- `Backend/security/`, `Backend/fyp1/`, `Backend/common/`, `Backend/api/`
- `frontend/react/src/pages/security`, `frontend/react/src/pages/fyp1`

## Build order
1. Agent skeleton + a fake module that sends test alerts
2. Security: enroll, verify, vault, gate, and the Login page
3. Malware: hash + YARA, then ransomware canary files, then ONNX and `native.rs`
4. Stego: image, audio, video
5. Dashboard, email and voice alerts

## Test
VM with snapshots, EICAR file, public stego datasets (BOSSBase, ALASKA). No live malware on the main machine.

## Deliverables
SRS, architecture diagram, working demo, test report.
