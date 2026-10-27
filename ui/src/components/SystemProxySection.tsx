// SPDX-License-Identifier: MIT

import { type SystemProxyView } from '../api'
import { usePolled } from '../data/StoreProvider'
import { InfoList, InfoPopover } from './InfoPopover'
import { CodeBlock, Notice } from './primitives'

/** What this machine's own proxy setting is doing, in one word plus the tone that goes
 *  with it. `enabled` is what the user asked for; `applied` is what actually happened,
 *  and the gap between them is the case worth naming. */
function machineState(view: SystemProxyView): { tone: string; label: string } {
  if (!view.supported) return { tone: 'pending', label: 'by hand only' }
  if (!view.enabled) return { tone: '', label: 'off' }
  if (view.applied) return { tone: 'running', label: 'pointing here' }
  return { tone: 'error', label: 'not applied' }
}

/** Whether the machine points somewhere app-tail did not put it. That is not a failure --
 *  it is someone else's configuration, and the reason this app never overwrites it
 *  without recording what was there. */
function foreign(view: SystemProxyView): boolean {
  return view.autoConfigUrl !== undefined && view.autoConfigUrl !== '' && !view.managed
}

export function SystemProxySection() {
  const system = usePolled('proxy.system')
  const view = system.data

  if (view === undefined) {
    // A failure here says nothing about the proxy above it, so it stays inside this
    // section rather than becoming the panel's headline.
    return system.error !== undefined ? (
      <div className="proxy-system">
        <Notice tone="warn">{system.error}</Notice>
      </div>
    ) : null
  }

  const state = machineState(view)

  return (
    <div className="proxy-system">
      <div className="proxy-system-head">
        <h3>This machine&rsquo;s proxy settings</h3>
        {/* The limits hold whether the switch is on or off -- they are what the platform
            does and does not reach, not an error about this moment. */}
        <InfoPopover label="this machine's proxy settings">
          <p>
            Point programs that read the system proxy setting at app-tail&rsquo;s own
            proxy, without configuring each one.
          </p>
          <InfoList items={view.capability.limits ?? []} />
        </InfoPopover>
        <span className={`status ${state.tone}`}>
          <span className="dot" aria-hidden="true" />
          {state.label}
        </span>
      </div>

      {view.applied && view.autoConfigUrl ? (
        <p className="hint">
          Programs that read the system proxy setting are using{' '}
          <code className="mono">{view.autoConfigUrl}</code>. Whatever was set before is
          recorded and put back when this is switched off.
        </p>
      ) : null}

      {foreign(view) ? (
        <Notice tone="info">
          Something else already points this machine at {view.autoConfigUrl}. app-tail
          records that value before replacing it, and restores it afterwards.
        </Notice>
      ) : null}

      {view.capability.reason ? (
        <Notice tone={view.capability.degraded ? 'warn' : 'info'}>
          {view.capability.reason}
        </Notice>
      ) : null}

      {view.manual.length > 0 ? (
        <details className="advanced">
          <summary>Change it yourself</summary>
          <div className="advanced-body">
            {view.manual.map((command) => (
              <div className="field" key={command.label}>
                <span className="field-caption">{command.label}</span>
                <CodeBlock text={command.command} />
              </div>
            ))}
          </div>
        </details>
      ) : null}
    </div>
  )
}
