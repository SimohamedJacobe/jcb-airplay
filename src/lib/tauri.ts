import { invoke } from '@tauri-apps/api/core'

// ─── Tauri IPC wrappers ────────────────────────────────────────────────────
// All `invoke` calls must go through this module — never call invoke() directly
// from components. This gives us a single typed interface to the Rust backend.

/**
 * Smoke-test greeting command — verifies IPC is functional.
 * @param name - Caller's name to include in the greeting.
 */
export async function greet(name: string): Promise<string> {
  return invoke<string>('greet', { name })
}

/**
 * Start the backend synthetic 60fps SMPTE YUV420p color-bar and radar generator.
 * @param width - Video frame width (default: 1920).
 * @param height - Video frame height (default: 1080).
 */
export async function startTestPattern(width = 1920, height = 1080): Promise<void> {
  await invoke('start_test_pattern', { width, height })
}

/**
 * Stop the synthetic test pattern generator.
 */
export async function stopTestPattern(): Promise<void> {
  await invoke('stop_test_pattern')
}

/**
 * Parsed zero-copy YUV420p video frame structure for GPU canvas consumption.
 */
export interface ParsedVideoFrame {
  width: number
  height: number
  timestamp: bigint
  yStride: number
  uvStride: number
  yPlane: Uint8Array
  uPlane: Uint8Array
  vPlane: Uint8Array
}

/**
 * Binary magic bytes for packed frame header: 'JCBF' (0x4A, 0x43, 0x42, 0x46).
 */
export const PACKED_FRAME_MAGIC = 0x4642434a // little-endian 'JCBF'

/**
 * Parse a raw packed binary video frame into planar YUV420p byte slices.
 * Format:
 * - 0..4: Magic 'JCBF' (4 bytes)
 * - 4..8: Width u32 LE (4 bytes)
 * - 8..12: Height u32 LE (4 bytes)
 * - 12..20: Timestamp u64 LE (8 bytes)
 * - 20..24: Y-stride u32 LE (4 bytes)
 * - 24..28: UV-stride u32 LE (4 bytes)
 * - 28..: Contiguous Y-plane, U-plane, V-plane
 *
 * @param raw - Raw binary buffer returned from Tauri IPC.
 * @returns ParsedVideoFrame with zero-copy views onto planar data, or null if invalid.
 */
export function parsePackedVideoFrame(raw: ArrayBuffer | Uint8Array | number[]): ParsedVideoFrame | null {
  let u8: Uint8Array
  if (raw instanceof ArrayBuffer) {
    u8 = new Uint8Array(raw)
  } else if (raw instanceof Uint8Array) {
    u8 = raw
  } else if (Array.isArray(raw)) {
    u8 = new Uint8Array(raw)
  } else {
    return null
  }

  if (u8.byteLength < 28) {
    return null
  }

  const view = new DataView(u8.buffer, u8.byteOffset, u8.byteLength)

  // Verify 'JCBF' magic header
  const magic = view.getUint32(0, true)
  if (magic !== PACKED_FRAME_MAGIC) {
    return null
  }

  const width = view.getUint32(4, true)
  const height = view.getUint32(8, true)
  const timestamp = view.getBigUint64(12, true)
  const yStride = view.getUint32(20, true)
  const uvStride = view.getUint32(24, true)

  if (width === 0 || height === 0) {
    return null
  }

  const yLen = width * height
  const uvLen = Math.floor(width / 2) * Math.floor(height / 2)
  const requiredLen = 28 + yLen + uvLen * 2

  if (u8.byteLength < requiredLen) {
    return null
  }

  // Create zero-copy sub-arrays without duplicating heap allocations
  const yPlane = u8.subarray(28, 28 + yLen)
  const uPlane = u8.subarray(28 + yLen, 28 + yLen + uvLen)
  const vPlane = u8.subarray(28 + yLen + uvLen, 28 + yLen + uvLen * 2)

  return {
    width,
    height,
    timestamp,
    yStride,
    uvStride,
    yPlane,
    uPlane,
    vPlane,
  }
}

/**
 * Fetch the latest decoded or synthetic video frame from the Rust backend.
 * Returns raw binary payload or null if no frame is currently available.
 */
export async function getLatestVideoFrame(): Promise<ParsedVideoFrame | null> {
  try {
    const raw = await invoke<ArrayBuffer | Uint8Array | number[]>('get_latest_video_frame')
    if (!raw) return null
    return parsePackedVideoFrame(raw)
  } catch (err) {
    console.debug('Failed to fetch video frame from backend IPC:', err)
    return null
  }
}
