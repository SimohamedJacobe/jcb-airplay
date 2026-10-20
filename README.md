# JCB AirPlay

> Ultra-low-latency iPhone AirPlay Screen Mirroring Receiver and zero-reencode DVR clip studio for PC.

Built with **Tauri v2** (Rust backend + React/TypeScript frontend).

---

## Features (Roadmap)

| Feature | Status |
|---|---|
| mDNS / Bonjour service advertisement | 🔲 Planned |
| RTSP session management | 🔲 Planned |
| FairPlay / AES-128 stream decryption | 🔲 Planned |
| H.264 / AAC frame pipeline + display | 🔲 Planned |
| Zero-reencode DVR clip capture | 🔲 Planned |
| DVR clip studio UI | 🔲 Planned |

---

## Quick Start

```powershell
# Prerequisites: Rust (stable), Node.js 20+
npm install
npm run tauri dev
```

## Verification

Every step must pass the Outside Judge before committing:

```powershell
.\scripts\verify_step.ps1
```

See [CONTRIBUTING.md](./CONTRIBUTING.md) for full details.

---

## Architecture

```
iPhone ──[Wi-Fi]──► mDNS discovery ──► RTSP session ──► FairPlay decrypt ──► H.264/AAC pipeline ──► Render
                                                                                                        │
                                                                                                    DVR buffer
                                                                                                        │
                                                                                                   Clip export (fMP4)
```

## License

Private — JCB © 2026
