# Contributing to JCB AirPlay

Welcome! JCB AirPlay is an ultra-low-latency iPhone AirPlay Screen Mirroring Receiver and
zero-reencode DVR clip studio for PC, built with Tauri v2 (Rust + React/TypeScript/Tailwind CSS).

---

## 🔴 The Golden Rule: The Outside Judge

> **No step in this project is considered complete until the Outside Judge script passes with
> zero warnings and zero errors.**

Every commit, every PR, every feature branch must satisfy:

```powershell
.\scripts\verify_step.ps1
```

This script runs in order:

| Check | Command | Requirement |
|---|---|---|
| Rust compilation | `cargo check` | Zero errors |
| Rust tests | `cargo test --no-fail-fast` | All tests pass |
| Rust lints | `cargo clippy -- -D warnings` | Zero warnings (warnings = errors) |
| TypeScript types | `npx tsc --noEmit` | Zero type errors |

If **any** of the above fails, the step is **not done**. Fix all issues before committing.

---

## 📁 Project Structure

```
jcb-airplay/
├── src/                    # React/TypeScript frontend
│   ├── components/         # Reusable UI components
│   ├── pages/              # Page-level components
│   ├── hooks/              # Custom React hooks
│   └── lib/                # Shared utilities & Tauri IPC wrappers
├── src-tauri/              # Rust backend (Tauri v2)
│   ├── src/
│   │   ├── main.rs         # Entry point
│   │   ├── lib.rs          # Library root, Tauri app builder
│   │   ├── mdns.rs         # mDNS service discovery (Bonjour/_airplay._tcp)
│   │   ├── rtsp.rs         # RTSP session management & SDP negotiation
│   │   ├── crypto.rs       # FairPlay/AES-128 key exchange & stream decryption
│   │   ├── media.rs        # H.264/AAC frame pipeline, render surface bridge
│   │   └── dvr.rs          # Zero-reencode DVR: clip capture, trim, export
│   ├── Cargo.toml          # Rust manifest
│   └── tauri.conf.json     # Tauri configuration
├── scripts/
│   └── verify_step.ps1     # Outside Judge — MUST PASS before any commit
├── CONTRIBUTING.md         # This file
└── README.md               # Project overview
```

---

## 🛠️ Development Setup

### Prerequisites

| Tool | Minimum Version | Install |
|---|---|---|
| Rust (stable) | 1.77+ | https://rustup.rs |
| Node.js | 20+ | https://nodejs.org |
| npm | 10+ | Bundled with Node.js |
| Tauri CLI | 2.x | `npm install` (devDependency) |
| WebView2 | Latest | Pre-installed on Windows 11 / auto-install |

### First-time Setup

```powershell
# 1. Install Rust
winget install Rustlang.Rustup
# Restart your terminal so cargo/rustc are on PATH

# 2. Install the stable toolchain
rustup toolchain install stable
rustup default stable

# 3. Install frontend dependencies
npm install

# 4. Verify everything builds
.\scripts\verify_step.ps1

# 5. Run in development mode
npm run tauri dev
```

---

## 📐 Architecture Principles

### Rust Backend Modules

| Module | Responsibility |
|---|---|
| `mdns` | Advertises `_airplay._tcp` and `_raop._tcp` services via mDNS; handles device discovery |
| `rtsp` | RTSP/1.0 server; SDP offer/answer; session lifecycle (SETUP → PLAY → TEARDOWN) |
| `crypto` | FairPlay SRP handshake; AES-128-CTR stream key derivation; per-packet IV management |
| `media` | Demux raw MIKEY/RTP → H.264 NAL / AAC ADTS; WGPUSurface render bridge for zero-copy display |
| `dvr` | Ring-buffer pre-roll; keyframe-aligned clip extraction; fragmented MP4 mux (no re-encode) |

### Frontend ↔ Backend IPC

- All inter-process calls go through Tauri's **typed command** system (`invoke`).
- Use the wrappers in `src/lib/tauri.ts` — never call `invoke` directly from components.
- Events from Rust → React travel through Tauri's **event** system (`listen`).

### Performance Rules

- **No re-encoding** anywhere in the hot path. DVR clips are extracted by copying raw NAL units.
- Render surfaces are managed in Rust; the frontend only holds a canvas element ID.
- Target: end-to-end AirPlay latency < 50 ms on a local Wi-Fi network.

---

## 🔁 Git Workflow

1. Branch from `main`: `git checkout -b feat/<scope>/<short-desc>`
2. Make atomic, focused commits using Conventional Commits:
   - `feat(mdns): advertise _airplay._tcp service`
   - `fix(crypto): correct AES-CTR IV rollover`
   - `refactor(media): extract NAL parser into separate fn`
3. Run `.\scripts\verify_step.ps1` — must pass.
4. Push and open a PR against `main`.

### Commit Scopes

`core` | `mdns` | `rtsp` | `crypto` | `media` | `dvr` | `ui` | `ci` | `docs`

---

## 🧪 Testing Policy

- **Every public Rust function** that contains logic must have at least one `#[test]`.
- Integration tests live in `src-tauri/tests/`.
- Frontend unit tests use Vitest (`npm run test`).
- The Outside Judge runs **all** Rust tests; TypeScript tests are run separately in CI.

---

## ⚠️ Clippy is Law

`cargo clippy -- -D warnings` is non-negotiable. All clippy warnings are treated as errors.
Do not use `#[allow(...)]` without a comment explaining why the lint does not apply.

---

## 📝 Code Style

- **Rust**: Follow `rustfmt` defaults. Run `cargo fmt` before committing.
- **TypeScript**: Follow the ESLint config. Run `npm run lint` before committing.
- **No `unwrap()` in production code** — use `?` or proper error handling.
- **No `console.log` in committed code** — use the structured logger.

---

## 🔒 Security

- Cryptographic primitives must come from audited crates (`aes`, `ring`, `srp`).
- Never log key material or session tokens.
- Keep all Apple FairPlay implementation details in `src-tauri/src/crypto.rs` only.

---

*Last updated: October 2026*
