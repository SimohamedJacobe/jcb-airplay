import { useState, useCallback } from 'react'
import { MirrorCanvas, type MirrorCanvasStats } from './components/MirrorCanvas'
import { startTestPattern, stopTestPattern, greet } from './lib/tauri'
import './App.css'

export function App() {
  const [isStreaming, setIsStreaming] = useState(false)
  const [currentMode, setCurrentMode] = useState<'landscape' | 'portrait'>('landscape')
  const [showHud, setShowHud] = useState(true)
  const [ipcGreeting, setIpcGreeting] = useState('')
  const [stats, setStats] = useState<MirrorCanvasStats>({
    fps: 60,
    width: 1920,
    height: 1080,
    isPortrait: false,
    renderer: 'webgl2',
    frameCount: 0,
  })

  const handleStartLandscape = async () => {
    try {
      await startTestPattern(1920, 1080)
      setIsStreaming(true)
      setCurrentMode('landscape')
    } catch (e) {
      console.error('Failed to start landscape test pattern:', e)
    }
  }

  const handleStartPortrait = async () => {
    try {
      // iPhone native screen mirror orientation: 1080x1920
      await startTestPattern(1080, 1920)
      setIsStreaming(true)
      setCurrentMode('portrait')
    } catch (e) {
      console.error('Failed to start portrait test pattern:', e)
    }
  }

  const handleStop = async () => {
    try {
      await stopTestPattern()
      setIsStreaming(false)
    } catch (e) {
      console.error('Failed to stop test pattern:', e)
    }
  }

  const handleVerifyIpc = async () => {
    try {
      const response = await greet('Studio Director')
      setIpcGreeting(response)
    } catch (e) {
      setIpcGreeting(`IPC Error: ${String(e)}`)
    }
  }

  const handleStatsUpdate = useCallback((newStats: MirrorCanvasStats) => {
    setStats(newStats)
  }, [])

  return (
    <div className="studio-app">
      {/* Studio Header */}
      <header className="studio-header">
        <div className="header-brand">
          <div className="brand-logo-glow" />
          <div className="brand-titles">
            <h1 className="brand-title">JCB AirPlay</h1>
            <span className="brand-tagline">Zero-CPU-Conversion WebGL2 BT.709 GPU Canvas</span>
          </div>
        </div>

        <div className="header-badges">
          <div className={`status-pill ${isStreaming ? 'live' : 'standby'}`}>
            <span className="pulse-dot" />
            <span>{isStreaming ? 'STREAMING 60 FPS' : 'STANDBY'}</span>
          </div>
          <div className="protocol-pill">AirPlay v2.5 / H.264</div>
        </div>
      </header>

      {/* Main Studio Viewport */}
      <main className="studio-main">
        <section className="viewport-stage" aria-label="AirPlay Mirroring Viewport">
          <div className="viewport-frame">
            <MirrorCanvas
              active={isStreaming}
              showHud={showHud}
              onStatsUpdate={handleStatsUpdate}
              className="studio-canvas"
            />
          </div>
        </section>

        {/* Studio Control Deck */}
        <section className="control-deck">
          <div className="controls-group primary-actions">
            <button
              id="btn-start-landscape"
              type="button"
              className={`studio-btn ${isStreaming && currentMode === 'landscape' ? 'active-btn' : ''}`}
              onClick={() => void handleStartLandscape()}
            >
              <span className="btn-icon">🖥️</span>
              <span>1080p60 SMPTE (16:9)</span>
            </button>

            <button
              id="btn-start-portrait"
              type="button"
              className={`studio-btn ${isStreaming && currentMode === 'portrait' ? 'active-btn' : ''}`}
              onClick={() => void handleStartPortrait()}
            >
              <span className="btn-icon">📱</span>
              <span>iPhone Portrait (9:16)</span>
            </button>

            <button
              id="btn-stop-stream"
              type="button"
              className="studio-btn danger-btn"
              disabled={!isStreaming}
              onClick={() => void handleStop()}
            >
              <span className="btn-icon">⏹️</span>
              <span>Stop Stream</span>
            </button>

            <button
              id="btn-toggle-hud"
              type="button"
              className={`studio-btn ghost-btn ${showHud ? 'btn-toggled' : ''}`}
              onClick={() => setShowHud((prev) => !prev)}
            >
              <span className="btn-icon">📊</span>
              <span>{showHud ? 'Hide HUD' : 'Show HUD'}</span>
            </button>
          </div>

          <div className="controls-group auxiliary-actions">
            <button
              id="btn-verify-ipc"
              type="button"
              className="studio-btn subtle-btn"
              onClick={() => void handleVerifyIpc()}
            >
              <span>Verify IPC</span>
            </button>
            {ipcGreeting && <span className="ipc-feedback">{ipcGreeting}</span>}
          </div>
        </section>

        {/* Telemetry Dashboard */}
        <section className="telemetry-grid">
          <div className="telemetry-card">
            <span className="card-label">Active Geometry</span>
            <div className="card-value">
              {stats.width} × {stats.height}
              <span className="card-sub">{stats.isPortrait ? '9:16 Portrait' : '16:9 Landscape'}</span>
            </div>
          </div>

          <div className="telemetry-card">
            <span className="card-label">GPU Render Engine</span>
            <div className="card-value highlight-accent">
              {stats.renderer === 'webgl2' ? 'WebGL2 (gl.R8)' : 'Canvas 2D Fallback'}
              <span className="card-sub">ITU-R BT.709 Rec. Direct GLSL</span>
            </div>
          </div>

          <div className="telemetry-card">
            <span className="card-label">Luma / Chroma Planes</span>
            <div className="card-value">
              {((stats.width * stats.height) / 1024).toFixed(0)} KB Y / {(((stats.width / 2) * (stats.height / 2)) / 1024).toFixed(0)} KB UV
              <span className="card-sub">Contiguous Zero-Copy Binary Payload</span>
            </div>
          </div>

          <div className="telemetry-card">
            <span className="card-label">Target Refresh Rate</span>
            <div className="card-value">
              {stats.fps > 0 ? stats.fps : 60} FPS
              <span className="card-sub">Hardware Synchronized</span>
            </div>
          </div>
        </section>
      </main>
    </div>
  )
}

export default App
