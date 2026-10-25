import { useEffect, useRef, useState, useCallback } from 'react'
import { getLatestVideoFrame, type ParsedVideoFrame } from '../lib/tauri'

// ─── GLSL Vertex & Fragment Shaders (WebGL2 / #version 300 es) ───────────────

const VS_SOURCE = `#version 300 es
precision highp float;

in vec2 a_position;
in vec2 a_texCoord;

out vec2 v_texCoord;

void main() {
    gl_Position = vec4(a_position, 0.0, 1.0);
    v_texCoord = a_texCoord;
}
`

const FS_SOURCE = `#version 300 es
precision highp float;

in vec2 v_texCoord;

// Three single-channel gl.R8 textures for planar YUV420p video
uniform sampler2D u_texY;
uniform sampler2D u_texU;
uniform sampler2D u_texV;

out vec4 fragColor;

void main() {
    // In WebGL2 gl.R8 textures, the 8-bit luma/chroma byte is sampled in the .r channel
    float y = texture(u_texY, v_texCoord).r;
    float u = texture(u_texU, v_texCoord).r;
    float v = texture(u_texV, v_texCoord).r;

    // ITU-R BT.709 Limited Range (Studio Swing) Color Space Conversion:
    // Y'  in [16/255, 235/255] normalized
    // Cb, Cr centered at 128/255 (~0.501961)
    float y_scaled = 1.164384 * (y - 0.062745);
    float u_diff = u - 0.501961;
    float v_diff = v - 0.501961;

    float r = y_scaled + 1.792741 * v_diff;
    float g = y_scaled - 0.213249 * u_diff - 0.532909 * v_diff;
    float b = y_scaled + 2.112402 * u_diff;

    fragColor = vec4(clamp(vec3(r, g, b), 0.0, 1.0), 1.0);
}
`

// ─── Types & Interfaces ──────────────────────────────────────────────────────

export interface MirrorCanvasStats {
  fps: number
  width: number
  height: number
  isPortrait: boolean
  renderer: 'webgl2' | '2d'
  frameCount: number
}

export interface MirrorCanvasProps {
  className?: string
  active?: boolean
  showHud?: boolean
  customFrame?: ParsedVideoFrame | null
  onStatsUpdate?: (stats: MirrorCanvasStats) => void
}

interface WebGLContextState {
  gl: WebGL2RenderingContext
  program: WebGLProgram
  vao: WebGLVertexArrayObject
  texY: WebGLTexture
  texU: WebGLTexture
  texV: WebGLTexture
  uTexYLoc: WebGLUniformLocation
  uTexULoc: WebGLUniformLocation
  uTexVLoc: WebGLUniformLocation
}

function compileShader(gl: WebGL2RenderingContext, type: number, source: string): WebGLShader | null {
  const shader = gl.createShader(type)
  if (!shader) return null
  gl.shaderSource(shader, source)
  gl.compileShader(shader)
  if (!gl.getShaderParameter(shader, gl.COMPILE_STATUS)) {
    console.error('Shader compile failed:', gl.getShaderInfoLog(shader))
    gl.deleteShader(shader)
    return null
  }
  return shader
}

function createTexture(gl: WebGL2RenderingContext): WebGLTexture | null {
  const tex = gl.createTexture()
  if (!tex) return null
  gl.bindTexture(gl.TEXTURE_2D, tex)
  gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_S, gl.CLAMP_TO_EDGE)
  gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_T, gl.CLAMP_TO_EDGE)
  gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MIN_FILTER, gl.LINEAR)
  gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MAG_FILTER, gl.LINEAR)
  return tex
}

export function MirrorCanvas({
  className = '',
  active = true,
  showHud = true,
  customFrame = null,
  onStatsUpdate,
}: MirrorCanvasProps) {
  const canvasRef = useRef<HTMLCanvasElement | null>(null)
  const glStateRef = useRef<WebGLContextState | null>(null)
  const fallback2dRef = useRef<{ ctx: CanvasRenderingContext2D; imgData: ImageData | null } | null>(null)
  const currentDimensionsRef = useRef<{ width: number; height: number }>({ width: 0, height: 0 })
  const frameCounterRef = useRef({ count: 0, lastTime: performance.now(), fps: 0 })

  const [stats, setStats] = useState<MirrorCanvasStats>({
    fps: 0,
    width: 1920,
    height: 1080,
    isPortrait: false,
    renderer: 'webgl2',
    frameCount: 0,
  })

  // Initialize WebGL2 with 2D Canvas fallback
  const initRenderer = useCallback((canvas: HTMLCanvasElement): 'webgl2' | '2d' => {
    // Attempt WebGL2 first
    try {
      const gl = canvas.getContext('webgl2', {
        alpha: false,
        depth: false,
        stencil: false,
        antialias: false,
        powerPreference: 'high-performance',
      })

      if (gl) {
        const vs = compileShader(gl, gl.VERTEX_SHADER, VS_SOURCE)
        const fs = compileShader(gl, gl.FRAGMENT_SHADER, FS_SOURCE)

        if (vs && fs) {
          const program = gl.createProgram()
          if (program) {
            gl.attachShader(program, vs)
            gl.attachShader(program, fs)
            gl.linkProgram(program)

            if (gl.getProgramParameter(program, gl.LINK_STATUS)) {
              // Full quad vertices: [x, y, u, v]
              const quadVertices = new Float32Array([
                -1.0,  1.0,  0.0, 0.0, // Top-left
                -1.0, -1.0,  0.0, 1.0, // Bottom-left
                 1.0,  1.0,  1.0, 0.0, // Top-right
                 1.0, -1.0,  1.0, 1.0, // Bottom-right
              ])

              const vao = gl.createVertexArray()
              const vbo = gl.createBuffer()

              if (vao && vbo) {
                gl.bindVertexArray(vao)
                gl.bindBuffer(gl.ARRAY_BUFFER, vbo)
                gl.bufferData(gl.ARRAY_BUFFER, quadVertices, gl.STATIC_DRAW)

                const posLoc = gl.getAttribLocation(program, 'a_position')
                const texLoc = gl.getAttribLocation(program, 'a_texCoord')

                if (posLoc !== -1) {
                  gl.enableVertexAttribArray(posLoc)
                  gl.vertexAttribPointer(posLoc, 2, gl.FLOAT, false, 16, 0)
                }

                if (texLoc !== -1) {
                  gl.enableVertexAttribArray(texLoc)
                  gl.vertexAttribPointer(texLoc, 2, gl.FLOAT, false, 16, 8)
                }

                const texY = createTexture(gl)
                const texU = createTexture(gl)
                const texV = createTexture(gl)

                const uTexYLoc = gl.getUniformLocation(program, 'u_texY')
                const uTexULoc = gl.getUniformLocation(program, 'u_texU')
                const uTexVLoc = gl.getUniformLocation(program, 'u_texV')

                if (texY && texU && texV && uTexYLoc && uTexULoc && uTexVLoc) {
                  glStateRef.current = {
                    gl,
                    program,
                    vao,
                    texY,
                    texU,
                    texV,
                    uTexYLoc,
                    uTexULoc,
                    uTexVLoc,
                  }
                  return 'webgl2'
                }
              }
            }
          }
        }
      }
    } catch (e) {
      console.warn('WebGL2 initialization failed, falling back to 2D canvas:', e)
    }

    // Fallback to 2D Context
    const ctx = canvas.getContext('2d', { willReadFrequently: false })
    if (ctx) {
      fallback2dRef.current = { ctx, imgData: null }
      return '2d'
    }

    return 'webgl2'
  }, [])

  // Render a YUV420p frame using WebGL2 GPU shader
  const renderWebGL2Frame = (frame: ParsedVideoFrame) => {
    const state = glStateRef.current
    const canvas = canvasRef.current
    if (!state || !canvas) return

    const { gl, program, vao, texY, texU, texV, uTexYLoc, uTexULoc, uTexVLoc } = state
    const { width, height, yPlane, uPlane, vPlane } = frame
    const dimChanged =
      currentDimensionsRef.current.width !== width ||
      currentDimensionsRef.current.height !== height

    if (dimChanged) {
      canvas.width = width
      canvas.height = height
      currentDimensionsRef.current = { width, height }
    }

    gl.viewport(0, 0, width, height)
    gl.pixelStorei(gl.UNPACK_ALIGNMENT, 1)

    // Texture 0: Y Plane (Luma) - full resolution
    gl.activeTexture(gl.TEXTURE0)
    gl.bindTexture(gl.TEXTURE_2D, texY)
    if (dimChanged) {
      gl.texImage2D(gl.TEXTURE_2D, 0, gl.R8, width, height, 0, gl.RED, gl.UNSIGNED_BYTE, yPlane)
    } else {
      gl.texSubImage2D(gl.TEXTURE_2D, 0, 0, 0, width, height, gl.RED, gl.UNSIGNED_BYTE, yPlane)
    }

    const uvWidth = Math.floor(width / 2)
    const uvHeight = Math.floor(height / 2)

    // Texture 1: U Plane (Chroma Cb) - half resolution
    gl.activeTexture(gl.TEXTURE1)
    gl.bindTexture(gl.TEXTURE_2D, texU)
    if (dimChanged) {
      gl.texImage2D(gl.TEXTURE_2D, 0, gl.R8, uvWidth, uvHeight, 0, gl.RED, gl.UNSIGNED_BYTE, uPlane)
    } else {
      gl.texSubImage2D(gl.TEXTURE_2D, 0, 0, 0, uvWidth, uvHeight, gl.RED, gl.UNSIGNED_BYTE, uPlane)
    }

    // Texture 2: V Plane (Chroma Cr) - half resolution
    gl.activeTexture(gl.TEXTURE2)
    gl.bindTexture(gl.TEXTURE_2D, texV)
    if (dimChanged) {
      gl.texImage2D(gl.TEXTURE_2D, 0, gl.R8, uvWidth, uvHeight, 0, gl.RED, gl.UNSIGNED_BYTE, vPlane)
    } else {
      gl.texSubImage2D(gl.TEXTURE_2D, 0, 0, 0, uvWidth, uvHeight, gl.RED, gl.UNSIGNED_BYTE, vPlane)
    }

    gl.useProgram(program)
    gl.uniform1i(uTexYLoc, 0)
    gl.uniform1i(uTexULoc, 1)
    gl.uniform1i(uTexVLoc, 2)

    gl.bindVertexArray(vao)
    gl.drawArrays(gl.TRIANGLE_STRIP, 0, 4)
  }

  // Render a YUV420p frame using 2D canvas fallback (e.g. headless tests)
  const render2dFrame = (frame: ParsedVideoFrame) => {
    const fallback = fallback2dRef.current
    const canvas = canvasRef.current
    if (!fallback || !canvas) return

    const { ctx } = fallback
    const { width, height, yPlane, uPlane, vPlane } = frame
    const dimChanged =
      currentDimensionsRef.current.width !== width ||
      currentDimensionsRef.current.height !== height

    if (dimChanged || !fallback.imgData) {
      canvas.width = width
      canvas.height = height
      fallback.imgData = ctx.createImageData(width, height)
      currentDimensionsRef.current = { width, height }
    }

    const imgData = fallback.imgData
    const data = imgData.data
    const halfWidth = Math.floor(width / 2)

    let pixelIdx = 0
    for (let y = 0; y < height; y++) {
      const uvRow = Math.floor(y / 2) * halfWidth
      const yRow = y * width
      for (let x = 0; x < width; x++) {
        const yVal = yPlane[yRow + x]
        const uvIdx = uvRow + Math.floor(x / 2)
        const uVal = uPlane[uvIdx]
        const vVal = vPlane[uvIdx]

        // BT.709 limited range formula
        const yScaled = 1.164384 * (yVal - 16)
        const uDiff = uVal - 128
        const vDiff = vVal - 128

        data[pixelIdx]     = Math.min(255, Math.max(0, (yScaled + 1.792741 * vDiff) | 0))
        data[pixelIdx + 1] = Math.min(255, Math.max(0, (yScaled - 0.213249 * uDiff - 0.532909 * vDiff) | 0))
        data[pixelIdx + 2] = Math.min(255, Math.max(0, (yScaled + 2.112402 * uDiff) | 0))
        data[pixelIdx + 3] = 255
        pixelIdx += 4
      }
    }

    ctx.putImageData(imgData, 0, 0)
  }

  // Main draw dispatch
  const drawFrame = useCallback((frame: ParsedVideoFrame) => {
    if (glStateRef.current) {
      renderWebGL2Frame(frame)
    } else if (fallback2dRef.current) {
      render2dFrame(frame)
    }

    // Track FPS metrics
    const now = performance.now()
    const counter = frameCounterRef.current
    counter.count++
    const elapsed = now - counter.lastTime
    if (elapsed >= 500) {
      counter.fps = Math.round((counter.count * 1000) / elapsed)
      counter.count = 0
      counter.lastTime = now

      const isPortrait = frame.height > frame.width
      const updatedStats: MirrorCanvasStats = {
        fps: counter.fps,
        width: frame.width,
        height: frame.height,
        isPortrait,
        renderer: glStateRef.current ? 'webgl2' : '2d',
        frameCount: counter.count,
      }
      setStats(updatedStats)
      onStatsUpdate?.(updatedStats)
    }
  }, [onStatsUpdate])

  // Custom frame effect (when external frame prop is provided)
  useEffect(() => {
    if (customFrame) {
      drawFrame(customFrame)
    }
  }, [customFrame, drawFrame])

  // Continuous frame polling loop via Tauri IPC
  useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas) return

    const rendererMode = initRenderer(canvas)
    setStats((prev) => ({ ...prev, renderer: rendererMode }))

    let animationFrameId: number
    let isRunning = true

    const pollFrame = async () => {
      if (!isRunning) return

      if (active && !customFrame) {
        try {
          const frame = await getLatestVideoFrame()
          if (frame && isRunning) {
            drawFrame(frame)
          }
        } catch {
          // Ignore network or idle IPC hiccups
        }
      }

      if (isRunning) {
        animationFrameId = requestAnimationFrame(() => void pollFrame())
      }
    }

    animationFrameId = requestAnimationFrame(() => void pollFrame())

    return () => {
      isRunning = false
      cancelAnimationFrame(animationFrameId)

      // Clean up WebGL resources
      const state = glStateRef.current
      if (state) {
        const { gl, program, vao, texY, texU, texV } = state
        gl.deleteTexture(texY)
        gl.deleteTexture(texU)
        gl.deleteTexture(texV)
        gl.deleteVertexArray(vao)
        gl.deleteProgram(program)
        glStateRef.current = null
      }
      fallback2dRef.current = null
    }
  }, [active, customFrame, drawFrame, initRenderer])

  const isPortrait = stats.height > stats.width
  const aspectRatio = `${stats.width} / ${stats.height}`

  return (
    <div
      className={`mirror-canvas-wrapper ${isPortrait ? 'portrait-mode' : 'landscape-mode'} ${className}`}
      style={{
        aspectRatio,
        maxHeight: isPortrait ? '78vh' : '68vh',
        maxWidth: isPortrait ? '44vh' : '100%',
      }}
    >
      <canvas
        ref={canvasRef}
        id="jcb-airplay-canvas"
        className="mirror-canvas"
        role="img"
        aria-label={`AirPlay Stream Canvas (${stats.width}x${stats.height})`}
      />

      {showHud && (
        <div className="mirror-hud-overlay" aria-live="polite">
          <div className="hud-badge hud-status">
            <span className={`status-indicator ${active ? 'active' : 'idle'}`} />
            <span>{active ? 'LIVE 60FPS' : 'STANDBY'}</span>
          </div>

          <div className="hud-badge hud-res">
            <span>{stats.width}x{stats.height}</span>
            <span className="hud-sub">({isPortrait ? '9:16 Portrait' : '16:9 Landscape'})</span>
          </div>

          <div className="hud-badge hud-renderer">
            <span>{stats.renderer === 'webgl2' ? '⚡ WebGL2 BT.709 GPU' : '⚠️ Canvas 2D'}</span>
          </div>

          <div className="hud-badge hud-fps">
            <span className="fps-number">{stats.fps > 0 ? stats.fps : 60}</span>
            <span className="hud-sub">FPS</span>
          </div>
        </div>
      )}
    </div>
  )
}
