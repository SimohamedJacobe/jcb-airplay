import { useState } from 'react'
import { greet } from './lib/tauri'
import './App.css'

/**
 * Root application component — placeholder for the JCB AirPlay UI.
 * The real mirroring canvas and DVR studio controls will be built in subsequent steps.
 */
function App() {
  const [greetMsg, setGreetMsg] = useState('')
  const [name, setName] = useState('')

  async function handleGreet() {
    const msg = await greet(name)
    setGreetMsg(msg)
  }

  return (
    <main className="app">
      <h1>JCB AirPlay</h1>
      <p className="subtitle">Ultra-low-latency AirPlay Receiver &amp; DVR Studio</p>

      <div className="ipc-demo">
        <input
          id="greet-input"
          onChange={(e) => setName(e.currentTarget.value)}
          placeholder="Enter a name..."
          value={name}
        />
        <button id="greet-button" type="button" onClick={() => void handleGreet()}>
          Test IPC
        </button>
      </div>
      {greetMsg && <p id="greet-msg">{greetMsg}</p>}
    </main>
  )
}

export default App
