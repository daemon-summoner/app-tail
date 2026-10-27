// SPDX-License-Identifier: MIT

import type { TunnelView } from '../api'
import { Panel } from './Panel'
import { CardSettings } from './settings/CardSettings'
import type { SettingsForm } from './settings/useSettingsDraft'

/** The derived field every connection carries: the suffix its own hosts answer under. */
const DNS_SUFFIX = 'dns.suffix'

function suffixOf(tunnel: TunnelView): string {
  const value = tunnel.settings[DNS_SUFFIX]
  return typeof value === 'string' ? value : ''
}

/**
 * Which connection answers for which names.
 *
 * This is the table that makes two networks with the same addresses usable at once, so it
 * is the one thing on this page a reader has to be able to find: a name carries the
 * connection it is on, and nothing has to be switched over to reach the other one.
 *
 * The rows report and change nothing. The suffix is derived from the connection's short
 * name, so it is changed by renaming the connection on its own page; the zone every one of
 * them hangs under is the card's own setting, because this is where its effect is visible.
 */
export function ConnectionNamesCard({
  tunnels,
  form,
}: {
  tunnels: readonly TunnelView[]
  form: SettingsForm
}) {
  const named = tunnels.filter((tunnel) => suffixOf(tunnel) !== '')
  if (named.length === 0) return null

  return (
    <Panel
      title="Names on your connections"
      wide
      info={
        <p>
          Each connection answers for names ending in its own suffix, so two networks using the same
          addresses are still told apart. The suffix comes from the connection&apos;s short name.
        </p>
      }
    >
      <div className="dns-list rows">
        <ul>
          {named.map((tunnel) => (
            <li key={tunnel.id}>
              <span className="mono">*.{suffixOf(tunnel)}</span>
              <span className="hint">
                <a href={`#/connections/${tunnel.type}/${tunnel.id}`}>{tunnel.name}</a>
                {tunnel.enabled ? '' : ' -- switched off, and it keeps its names'}
              </span>
            </li>
          ))}
        </ul>
      </div>

      {/* The half people otherwise discover by watching a browser fail. app-tail holds these
      networks inside its own process, so a name on one reaches it through app-tail or not at
      all -- and saying so here is cheaper than the bug report. */}
      <p className="hint">
        These names reach your networks through app-tail: its proxies, its forwards, and its
        auto-config file. Asked of this machine&apos;s own resolver they are answered here as no
        such name, because nothing outside app-tail can route those networks.
      </p>

      {/* The zone every suffix above hangs under, which is the one part of a name that is not
      the connection's own. The module switch in the same group belongs to the tailnet DNS
      card, and is left there. */}
      <CardSettings form={form} groups={['dns']} omit={['dns.enabled']} collapseLabel="Naming" />
    </Panel>
  )
}
