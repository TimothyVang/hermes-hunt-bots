import { Button, host, useValue } from '@hermes/plugin-sdk'
import { atom } from 'nanostores'
import type { KeyboardEvent, PointerEvent } from 'react'
import { useCallback, useEffect, useMemo, useRef, useState } from 'react'

const keys: Record<string, string> = {
  Enter: 'ret', Escape: 'esc', Backspace: 'backspace', Tab: 'tab', Space: 'spc',
  ArrowUp: 'up', ArrowDown: 'down', ArrowLeft: 'left', ArrowRight: 'right',
  ShiftLeft: 'shift', ShiftRight: 'shift_r', ControlLeft: 'ctrl', ControlRight: 'ctrl_r',
  AltLeft: 'alt', AltRight: 'alt_r', MetaLeft: 'meta_l', MetaRight: 'meta_r',
  Minus: 'minus', Equal: 'equal', BracketLeft: 'bracket_left', BracketRight: 'bracket_right',
  Semicolon: 'semicolon', Quote: 'apostrophe', Backquote: 'grave_accent', Backslash: 'backslash',
  Comma: 'comma', Period: 'dot', Slash: 'slash', CapsLock: 'caps_lock',
  Home: 'home', End: 'end', PageUp: 'pgup', PageDown: 'pgdn', Insert: 'insert', Delete: 'delete'
}

export function QemuConsolePane() {
  const [status, setStatus] = useState<'stopped' | 'starting' | 'running' | 'error'>('stopped')
  const [available, setAvailable] = useState(false)
  const [developerSmokeAvailable, setDeveloperSmokeAvailable] = useState(false)
  const [owned, setOwned] = useState(false)
  const [networkEnabled, setNetworkEnabled] = useState(false)
  const [hasDisk, setHasDisk] = useState(false)
  const [input, setInput] = useState(false)
  const [inputReleaseFailed, setInputReleaseFailed] = useState(false)
  const [frame, setFrame] = useState<string | null>(null)
  const [error, setError] = useState('')
  const pane = useRef<HTMLDivElement>(null)
  const heldKeys = useRef(new Set<string>())
  const $visible = useMemo(
    () => (typeof host.paneVisibility === 'function' ? host.paneVisibility('hermes-bots:qemu-console') : atom(false)),
    []
  )
  const visible = useValue($visible)
  const refresh = useCallback(async () => {
    try {
      const value = await window.hermesDesktop.qemu.status()
      setStatus(value.state); setOwned(value.owned); setAvailable(value.available); setDeveloperSmokeAvailable(value.developerSmokeAvailable)
      setHasDisk(value.hasDisk); setInput(value.inputEnabled); setNetworkEnabled(value.networkEnabled)
      setInputReleaseFailed(value.inputReleaseFailed)
      if (value.inputReleaseFailed) setError('Guest input release was not acknowledged. Control remains disabled; explicitly power off the VM before taking control again.')
    } catch (e) { setError(e instanceof Error ? e.message : String(e)) }
  }, [])
  useEffect(() => {
    let live = true
    void window.hermesDesktop.qemu.setPaneVisible(visible).then(() => {
      if (live && visible) void refresh()
    }).catch(e => { if (live) setError(e instanceof Error ? e.message : String(e)) })
    if (!visible) {
      setFrame(null)
      setInput(false)
    }
    const poll = visible ? window.setInterval(() => { void refresh() }, 1200) : undefined
    return () => {
      live = false
      window.clearInterval(poll)
      void window.hermesDesktop.qemu.setPaneVisible(false)
        .catch(e => host.notifyError(e, 'Could not release the QEMU console'))
    }
  }, [refresh, visible])
  useEffect(() => {
    if (!input) heldKeys.current.clear()
    const blur = () => {
      if (!input) return
      void window.hermesDesktop.qemu.inputControl(false).then(refresh)
        .catch(e => host.notifyError(e, 'Could not release QEMU input control'))
        .finally(() => { setInput(false); heldKeys.current.clear() })
    }
    window.addEventListener('blur', blur)
    return () => window.removeEventListener('blur', blur)
  }, [input, refresh])
  useEffect(() => {
    if (!visible || status !== 'running') { setFrame(null); return }
    let live = true
    const poll = window.setInterval(() => {
      void window.hermesDesktop.qemu.capture().then(value => { if (live) setFrame(value) }).catch(e => { if (live) setError(e instanceof Error ? e.message : String(e)) })
    }, 750)
    return () => { live = false; window.clearInterval(poll) }
  }, [status, visible])
  const act = async (operation: () => Promise<unknown>) => {
    setError('')
    try { await operation(); await refresh() } catch (e) { setError(e instanceof Error ? e.message : String(e)); await refresh() }
  }
  const key = (event: KeyboardEvent, down: boolean) => {
    if (!input || (down && event.target !== pane.current)) return
    const qcode = keys[event.code] || (/^Key[A-Z]$/.test(event.code) ? event.code.slice(3).toLowerCase()
      : /^Digit[0-9]$/.test(event.code) ? event.code.slice(5)
        : /^F([1-9]|1[0-9]|2[0-4])$/.test(event.code) ? event.code.toLowerCase() : '')
    if (!qcode) return
    event.preventDefault()
    if (down && heldKeys.current.has(qcode)) return
    if (down) heldKeys.current.add(qcode)
    else heldKeys.current.delete(qcode)
    void window.hermesDesktop.qemu.key(qcode, down).catch(e => setError(e instanceof Error ? e.message : String(e)))
  }
  const mouse = (event: PointerEvent<HTMLImageElement>, button?: 'left' | 'right', down?: boolean) => {
    if (!input) return
    event.preventDefault()
    if (down) {
      pane.current?.focus()
      event.currentTarget.setPointerCapture(event.pointerId)
    } else if (down === false && event.currentTarget.hasPointerCapture(event.pointerId)) {
      event.currentTarget.releasePointerCapture(event.pointerId)
    }
    const bounds = event.currentTarget.getBoundingClientRect()
    const x = Math.round(Math.max(0, Math.min(1, (event.clientX - bounds.left) / bounds.width)) * 32767)
    const y = Math.round(Math.max(0, Math.min(1, (event.clientY - bounds.top) / bounds.height)) * 32767)
    void window.hermesDesktop.qemu.pointer(x, y, button, down).catch(e => setError(e instanceof Error ? e.message : String(e)))
  }
  return <div ref={pane} tabIndex={input ? 0 : -1} onKeyDown={event => key(event, true)} onKeyUp={event => key(event, false)} onBlur={event => {
    if (input && event.relatedTarget instanceof Node && !pane.current?.contains(event.relatedTarget)) {
      setInput(false)
      void window.hermesDesktop.qemu.inputControl(false).catch(e => host.notifyError(e, 'Could not release QEMU input control'))
    }
  }} aria-label="Local QEMU boot console" style={{ display: 'flex', flexDirection: 'column', gap: 10, height: '100%', padding: 12, outline: 'none' }}>
    <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
      <strong>Local QEMU boot console</strong><span>{!available ? 'QEMU runtime unavailable — stage an owned Windows x64 engine' : status === 'running' ? `Running — guest network ${networkEnabled ? 'enabled for this boot' : 'disabled'}` : status === 'starting' ? 'Starting' : status === 'error' ? owned ? 'VM control failed — process still owned' : 'Launch failed' : 'Stopped'}</span>
      {!owned || status === 'starting' ? <>
        <Button disabled={!available || status === 'starting'} onClick={() => void act(() => window.hermesDesktop.qemu.start('install'))}>Install from ISO…</Button>
        {hasDisk && <Button disabled={!available || status === 'starting'} onClick={() => void act(() => window.hermesDesktop.qemu.start('boot-existing'))}>Boot existing VM</Button>}
        {developerSmokeAvailable && <Button disabled={!available || status === 'starting'} onClick={() => void act(() => window.hermesDesktop.qemu.start('firmware-smoke'))}>Firmware smoke (diskless)</Button>}
      </> : <>
        <Button disabled={status !== 'running'} onClick={() => void act(() => window.hermesDesktop.qemu.stop(true))}>Request guest shutdown</Button>
        <Button onClick={() => void act(() => window.hermesDesktop.qemu.stop(false))}>Power off immediately</Button>
        <Button disabled={status !== 'running' || inputReleaseFailed} onClick={() => void act(async () => { await window.hermesDesktop.qemu.inputControl(!input); if (!input) pane.current?.focus() })}>{input ? 'Release keyboard/mouse control' : 'Take keyboard/mouse control'}</Button>
      </>}
    </div>
    <div style={{ flex: 1, minHeight: 220, display: 'grid', placeItems: 'center', background: '#111', overflow: 'hidden' }}>
      {frame ? <img alt="QEMU firmware or guest console" src={frame} onContextMenu={event => event.preventDefault()} onPointerMove={event => mouse(event)} onPointerDown={event => {
        if (event.button === 0 || event.button === 2) mouse(event, event.button === 2 ? 'right' : 'left', true)
      }} onPointerUp={event => {
        if (event.button === 0 || event.button === 2) mouse(event, event.button === 2 ? 'right' : 'left', false)
      }} onPointerCancel={() => {
        setInput(false)
        void window.hermesDesktop.qemu.inputControl(false).catch(e => host.notifyError(e, 'Could not release QEMU pointer control'))
      }} style={{ maxWidth: '100%', maxHeight: '100%', objectFit: 'contain', imageRendering: 'pixelated', userSelect: 'none' }} /> : <span style={{ color: '#aaa' }}>{status === 'running' ? 'Waiting for the first QEMU frame…' : 'No guest console is running.'}</span>}
    </div>
    <small>This is the VM boot console, not the remote Hermes Bot Screen. No guest login or OS readiness is implied. Keyboard and mouse input are disabled until you explicitly take control.</small>
    {error && <div role="alert">{error}</div>}
  </div>
}
