// SPDX-License-Identifier: MIT

import { type PrefFieldView, type PrefsView } from '../api'
import { Panel } from './Panel'
import { Notice } from './primitives'

/** How one value reads. These are the node's own preferences, so a bare `true` says
 *  nothing about what is on: the label carries the subject and this carries the state. */
function shown(value: PrefFieldView['stored']): string {
  // An empty list setting arrives as null, because a nil Go slice marshals to null
  // rather than to []. Falling through to the string branch would return null itself,
  // and the first caller to treat that as a string takes the whole dashboard down.
  if (value === null || value === undefined) return 'Not set'
  if (typeof value === 'boolean') return value ? 'On' : 'Off'
  if (typeof value === 'number') return String(value)
  // A list setting -- the networks this device offers to carry -- reads as its entries.
  // Rendered as an array it would arrive with no separators at all.
  if (Array.isArray(value)) return value.length === 0 ? 'None' : value.join(', ')
  return value === '' ? 'Not set' : value
}

/** What one setting is doing, from the node's side. The interesting case is the third:
 *  stored here, not what the node holds — which is invisible without saying it. */
function state(field: PrefFieldView, known: boolean): { text: string; stale: boolean } {
  if (!known) return { text: 'Waiting for the tailnet node', stale: true }
  if (field.inForce) return { text: 'In force', stale: false }
  if (field.live === undefined || field.live === null) {
    return { text: 'Waiting for the tailnet node', stale: true }
  }
  return { text: `The node has it ${shown(field.live).toLowerCase()}`, stale: true }
}

/** The settings app-tail keeps on the tailnet node rather than on this machine.
 *
 *  It exists because these are the only settings whose value lives somewhere this app
 *  does not control: saved here, applied there. A save that stored fine and never
 *  reached the tailnet — the node was down, or something else changed it back — would
 *  otherwise look identical to one that worked. */
export function PrefsCard({ view }: { view: PrefsView }) {
  return (
    <Panel
      title="Tailnet settings"
      info={
        <>
          <p>
            These settings are held by the tailnet node itself, so they apply across your
            tailnet rather than only on this machine.
          </p>
          <p>
            Each row shows what app-tail stored beside what the node is actually running
            with. The two differ while the node is down, or when something else changed a
            value back.
          </p>
        </>
      }
    >
      <dl className="proxy-counters">
        {(view.fields ?? []).map((field) => {
          const { text, stale } = state(field, view.known)
          return (
            <div key={field.key}>
              <dt title={text}>{field.label}</dt>
              <dd className={stale ? 'stale' : undefined}>
                {shown(field.stored)}
                <span className="hint"> — {text}</span>
              </dd>
            </div>
          )
        })}
      </dl>

      {view.capability.reason ? (
        <Notice tone={view.capability.degraded ? 'warn' : 'info'}>
          {view.capability.reason}
        </Notice>
      ) : null}
    </Panel>
  )
}
