// SPDX-License-Identifier: MIT

import { useCallback, useState } from 'react'

import { ApprovalBanner } from '../components/ApprovalBanner'
import { ConnectionCard } from '../components/ConnectionCard'
import { TagSetupDialog } from '../components/TagSetupDialog'
import { TrafficCard } from '../components/TrafficCard'
import { Notice } from '../components/primitives'
import type { SettingsForm } from '../components/settings/useSettingsDraft'
import { usePolled, useStore } from '../data/StoreProvider'
import { BlocklistHero } from './dashboard/BlocklistHero'
import { InspectionHero } from './dashboard/InspectionHero'
import { InternetHero } from './dashboard/InternetHero'
import { PathsHero } from './dashboard/PathsHero'
import { ResolverHero } from './dashboard/ResolverHero'
import { HEROES } from './dashboard/heroes'
import { TunnelTiles } from './dashboard/TunnelTiles'

/**
 * The page the dashboard opens on: the four switches somebody comes here to flip, whether
 * the tailnet is reachable, how this machine reaches it, and what is moving right now.
 *
 * Each hero card carries one control and a gear to the page with the rest, so the whole
 * of a feature is never on this page and the one thing worth flipping always is.
 */
export function DashboardPage({ form }: { form: SettingsForm }) {
  const [tags, setTags] = useState(false)
  const store = useStore()

  const status = usePolled('status')
  const tunnels = usePolled('tunnels')
  const forwards = usePolled('forwards')
  const automap = usePolled('automap')
  const proxy = usePolled('proxy')
  const tun = usePolled('tun')
  const fabric = usePolled('fabric')
  const traffic = usePolled('traffic')
  const egress = usePolled('egress')
  const dns = usePolled('dns')
  const dnsBlock = usePolled('dnsBlock')
  const ips = usePolled('ips')

  // A change made here can move anything: bringing the node up starts the forwards, which
  // changes the tiles and the graph together.
  const refreshAll = useCallback(() => store.refreshAll(), [store])

  return (
    <>
      {/* First, because every switch below that needs it is on and doing nothing until an
          administrator says yes. */}
      <ApprovalBanner approvals={status.data?.approvals} onApproved={refreshAll} />

      {/* The switches, before the report of what the machine is currently doing. Every
          hero writes through the settings form, so none is drawn before the schema has
          arrived: their rows are the choices the agent says it will accept. */}
      {form.loaded ? (
        <div className="deck hero-deck">
          <InternetHero form={form} view={egress.data} />
          <ResolverHero form={form} view={dns.data?.system} />
          <BlocklistHero form={form} view={dnsBlock.data} onChanged={refreshAll} />
          <InspectionHero form={form} view={ips.data} onChanged={refreshAll} />
        </div>
      ) : form.error !== undefined ? (
        // The reason is the form's own notice at the top of the page; this says what is
        // missing from this one.
        <Notice tone="error">The settings could not be read, so the switches are not shown.</Notice>
      ) : (
        <HeroDeckSkeleton />
      )}

      {status.data ? (
        <ConnectionCard
          status={status.data}
          onChanged={refreshAll}
          onSetupTags={() => setTags(true)}
        />
      ) : status.loading ? (
        <section className="panel">
          <div className="connection">
            <span className="status pending">
              <span className="dot" aria-hidden="true" />
              Connecting to the agent…
            </span>
          </div>
        </section>
      ) : null}

      {/* Which networks, before how they are reached: the second question is only worth
          asking once the first has an answer. */}
      {tunnels.data?.length ? <TunnelTiles tunnels={tunnels.data} /> : null}

      <PathsHero
        form={form}
        forwards={forwards.data ?? []}
        automap={automap.data}
        proxy={proxy.data}
        tun={tun.data}
        fabric={fabric.data}
        onChanged={refreshAll}
      />

      <div className="deck">
        <TrafficCard view={traffic.data} proxy={proxy.data} form={form} />
      </div>

      {tags ? <TagSetupDialog onClose={() => setTags(false)} /> : null}
    </>
  )
}

/** The four hero cards' outlines, shown while the settings schema is on its way. Each
 *  has the name it will carry, so the page does not rearrange itself when they arrive. */
function HeroDeckSkeleton() {
  return (
    <div className="deck hero-deck" aria-busy="true" aria-label="Reading settings">
      {HEROES.slice(0, 4).map((hero) => (
        <section className="panel" key={hero.id} aria-label={hero.label}>
          <div className="panel-head">
            <h2>{hero.label}</h2>
          </div>
          <div className="panel-body">
            <span className="skeleton tall wide" />
            <span className="skeleton half" />
          </div>
        </section>
      ))}
    </div>
  )
}
