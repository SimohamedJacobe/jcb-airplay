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
