// SPDX-License-Identifier: MIT

// Where everything your connections do not carry goes.
//
// It is on this page rather than on a connection's own page because it is a statement
// about this machine: one connection carries the machine's internet traffic and the
// others do not, so a control sitting on one connection would be invisible from every
// other one.
//
// The card holds the choice and what came of it together, because those are two different
// questions and only the second one can go wrong. A connection can be chosen and carrying
// nothing -- its server has no exit node, or it is switched off -- and the traffic then
// leaves this machine exactly as it did before, with the setting still reading "through my
// connection". Nothing else on the machine would say which of the two is true.

import { Notice } from '../primitives'
import { Panel } from '../Panel'
import { CardSettings } from '../settings/CardSettings'
import type { SettingsForm } from '../settings/useSettingsDraft'
import type { EgressMember, EgressView } from '../../api'

/** The group the whole card renders, and the two fields in it. The picker is hidden
 *  rather than removed while the traffic goes out directly: the id it holds is kept on
 *  purpose so switching back does not mean choosing again. */
const GROUP = 'egress'
const MODE_KEY = 'egress.mode'
const TUNNEL_KEY = 'egress.tunnelId'
const MEMBERS_KEY = 'egress.multi.tunnelIds'
const SHAPE_KEY = 'egress.multi.shape'
/** The kill switch is read only while one connection carries the traffic: several
 *  connections hold it whether or not it is on, and going out of this machine directly is
 *  the setting that says this machine's own network is where the traffic goes. */
const KILL_KEY = 'egress.killSwitch'

/** THROUGH_TUNNEL mirrors config.EgressTunnel: the one mode with a connection to name.
 *  SHARED mirrors config.EgressMulti, where the connection to name is a set of them. */
const THROUGH_TUNNEL = 'tunnel'
const SHARED = 'multi'

/** CASCADE mirrors config.EgressCascade: the set is one route through all of them in order
 *  rather than several ways out, which is a different reading of the same member list. */
const CASCADE = 'cascade'

export function EgressCard({ form, view, error }: {
  form: SettingsForm
  view: EgressView | undefined
  error?: string | undefined
}) {
  const field = form.available.find((f) => f.key === MODE_KEY)
  if (field === undefined) return null

  const group = form.groups.find((g) => g.id === GROUP)
  // The draft rather than the served view, so choosing a connection appears the moment
  // the mode is switched instead of after the next poll.
  const draft = form.bind(field).value
  const mode = typeof draft === 'string' ? draft : ''
  const throughTunnel = mode === THROUGH_TUNNEL
  const shared = mode === SHARED
  const limits = view?.limits ?? []
  // The rows come from the served view because they are about what is running, but the
  // draft decides whether to show them at all: a view still being polled under the previous
  // mode would list connections nothing is using.
  const members = shared ? (view?.members ?? []) : []
  // The shape comes from the view and not the draft: it decides how the rows below read,
  // and those rows are what is running. A shape just switched in the draft applies to them
  // on the next poll, when the connections it describes are the ones actually carrying.
  const chained = shared && view?.shape === CASCADE

  return (
    <Panel
      title={group?.label ?? field.label}
      wide
      info={<p>{group?.description}</p>}
      status={statusOf(mode, view)}
    >
      {/* Said before the picker: while this is showing, the setting below is not in
          force and the traffic is leaving this machine the way it always has. */}
      {(throughTunnel || shared) && view !== undefined && !view.carrying && view.reason ? (
        <Notice tone="error">{view.reason}</Notice>
      ) : null}

      {/* The promise, while it is being kept. Said on the card rather than left to the
          checkbox below it: what the switch does is only visible at the moment the
          connection stops carrying, which is the moment nobody is reading a checkbox. */}
      {throughTunnel && view?.killSwitch === true && view.carrying ? (
        <Notice tone="info">
          Held rather than leaked: while this connection cannot carry it, internet traffic stops
          here instead of leaving over whatever network this machine is on.
        </Notice>
      ) : null}

      {error ? <Notice tone="error">{error}</Notice> : null}

      {/* What choosing this connection does not do. A connection carrying the traffic
          whose names are still looked up here leaves the list of what is being visited on
          this network, which is most of what someone routing their traffic away wanted to
          stop -- and it is invisible from anywhere else. */}
      {(throughTunnel || shared) && limits.length > 0 ? (
        <ul className="tunnel-limits">
          {limits.map((limit) => (
            <li key={limit}>{limit}</li>
          ))}
        </ul>
      ) : null}

      {/* One row per connection carrying it, because that is what the mode does: shared,
          each carries its own share and one of them being down moves the destinations that
          were on it; chained, each carries the next and one being down stops the route
          there. A single line for the set could say neither. */}
      {members.length > 0 ? (
        <ul className="egress-members">
          {members.map((member, index) => (
            <li key={member.tunnelId}>
              {/* The position is the setting in a chain rather than a presentation of it:
                  which connection is first and which is last is the whole choice, since
                  the first sees who you are and the last sees where you went. */}
              {chained ? (
                <span className="egress-member-hop">
                  {member.exit === true ? `hop ${index + 1}, out` : `hop ${index + 1}`}
                </span>
              ) : null}
              <span className="egress-member-name">{member.tunnelName ?? member.tunnelId}</span>
              <span
                className={`status ${statusToneOf(member)}`}
                title={member.reason ?? undefined}
              >
                <span className="dot" aria-hidden="true" />
                {statusWordOf(member)}
              </span>
              {member.reason ? <span className="hint">{member.reason}</span> : null}
              {(member.limits ?? []).map((limit) => (
                <span className="hint" key={limit}>
                  {limit}
                </span>
              ))}
            </li>
          ))}
        </ul>
      ) : null}

      <CardSettings
        form={form}
        groups={[GROUP]}
        omit={[
          ...(throughTunnel ? [] : [TUNNEL_KEY, KILL_KEY]),
          ...(shared ? [] : [MEMBERS_KEY, SHAPE_KEY]),
        ]}
      />
    </Panel>
  )
}

/** A hop that has not started because the one before it has not is neither carrying nor
 *  failed. Every start of a chain passes through that state, and painting it red would put
 *  a failure on the card every single time the app starts. */
function statusToneOf(member: EgressMember) {
  if (member.carrying) return 'running'
  return member.waiting === true ? 'pending' : 'error'
}

function statusWordOf(member: EgressMember) {
  if (member.carrying) return 'carrying'
  return member.waiting === true ? 'waiting' : 'not carrying'
}

/** statusOf is the head's dot and word: what is happening, not what was asked for. The
 *  two disagree exactly when a chosen connection cannot carry it, which is the state this
 *  card exists to show. */
function statusOf(mode: string, view: EgressView | undefined) {
  if (mode !== THROUGH_TUNNEL && mode !== SHARED) {
    return { tone: 'off', label: 'leaving this machine' }
  }
  if (view === undefined) return { tone: 'pending', label: 'reading' }
  if (view.carrying) {
    return { tone: 'running', label: 'carrying', detail: carryingDetail(mode, view) }
  }
  // Held and not-carrying are different outcomes: one stops the traffic here, the other
  // leaves it going out the way it always has.
  return { tone: 'error', label: view.held === true ? 'held' : 'not carrying' }
}

/** What is carrying it, in one line. A set is counted rather than named, because naming one
 *  of several would read as the only one carrying it -- but a chain has a connection worth
 *  naming, the last one, since that is the address the internet sees. */
function carryingDetail(mode: string, view: EgressView) {
  if (mode !== SHARED) return view.tunnelName ?? view.tunnelId
  const members = view.members ?? []
  if (view.shape === CASCADE) {
    const exit = members.find((m) => m.exit === true)
    const out = exit?.tunnelName ?? exit?.tunnelId
    return out === undefined
      ? `${members.length} connections in a chain`
      : `${members.length} connections, out of ${out}`
  }
  return `${members.filter((m) => m.carrying).length} of ${members.length} connections`
}
