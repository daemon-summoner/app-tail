// SPDX-License-Identifier: MIT

import { ConnectionNamesCard } from '../components/ConnectionNamesCard'
import { DnsBlockCard } from '../components/DnsBlockCard'
import { DnsCard } from '../components/DnsCard'
import { SystemDnsCard } from '../components/SystemDnsCard'
import type { SettingsForm } from '../components/settings/useSettingsDraft'
import { usePolled } from '../data/StoreProvider'
import { href, type DnsSectionId } from '../lib/router'

/**
 * Name resolution, one page per half of it.
 *
 * Its own section rather than a page under Settings because the resolver is about the
 * whole machine and has nothing to do with a tailnet: it works, and matters, on a machine
 * that is not signed in to one. Each page polls only what it draws, so opening the
 * resolver does not poll every connection for its names.
 */
export function DnsPage({
  section,
  form,
}: {
  section: DnsSectionId | undefined
  form: SettingsForm
}) {
  switch (section) {
    case 'resolver':
      return <ResolverSection form={form} />
    case 'blocklist':
      return <BlocklistSection form={form} />
    case 'names':
      return <NamesSection form={form} />
    default:
      return <NoSuchSection />
  }
}

function ResolverSection({ form }: { form: SettingsForm }) {
  const dns = usePolled('dns')
  return (
    <div className="deck">
      {dns.data?.system ? (
        <SystemDnsCard view={dns.data.system} form={form} />
      ) : dns.data ? (
        // An agent older than this feature sends no system half at all, and a card
        // rendered from nothing would claim a machine-wide resolver this build cannot
        // switch. The page says so instead of standing empty.
        <section className="panel" aria-label="No system resolver">
          <div className="panel-body">
            <p className="hint">
              This agent does not carry the machine-wide resolver. The names your
              connections answer for are under{' '}
              <a href={href('dns', 'names')}>Names</a>.
            </p>
          </div>
        </section>
      ) : null}
    </div>
  )
}

function BlocklistSection({ form }: { form: SettingsForm }) {
  const dnsBlock = usePolled('dnsBlock')
  return (
    <div className="deck">
      {dnsBlock.data ? (
        <DnsBlockCard view={dnsBlock.data} form={form} onChanged={dnsBlock.refresh} />
      ) : null}
    </div>
  )
}

function NamesSection({ form }: { form: SettingsForm }) {
  const dns = usePolled('dns')
  const tunnels = usePolled('tunnels')
  return (
    <div className="deck">
      <ConnectionNamesCard tunnels={tunnels.data ?? []} form={form} />
      {dns.data ? <DnsCard view={dns.data} form={form} tunnels={tunnels.data ?? []} /> : null}
    </div>
  )
}

/** A stale link is the usual way someone gets here, so it says where they are and offers
 *  the way back rather than quietly showing a different page. */
function NoSuchSection() {
  return (
    <section className="panel" aria-label="No such section">
      <div className="panel-body">
        <p>That DNS section is not part of this dashboard.</p>
        <p>
          <a href={href('dns')}>Open the system resolver</a>
        </p>
      </div>
    </section>
  )
}
