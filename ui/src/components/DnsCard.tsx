// SPDX-License-Identifier: MIT

import type { DNSView, TunnelView } from '../api'
import { Names } from './dnsLists'
import { InfoList, InfoPopover } from './InfoPopover'
import { ModuleOff } from './ModuleOff'
import { Panel } from './Panel'
import { ModuleSwitch } from './settings/CardSettings'
import type { SettingsForm } from './settings/useSettingsDraft'
import { Notice } from './primitives'

function dnsState(view: DNSView): { tone: string; label: string } {
  if (!view.capability.available) return { tone: 'off', label: 'off' }
  if (view.capability.degraded)
    return { tone: 'pending', label: 'not resolving through your tailnet' }
  return { tone: 'running', label: 'resolving through your tailnet' }
}

/** The split-DNS suffixes. These are the names that resolve for app-tail and nowhere else
 *  on the machine, which is precisely the surprise this card exists to explain. */
function SplitDNS({ view }: { view: DNSView }) {
  const routes = view.routes ?? []
  if (routes.length === 0) return null
  return (
    <div className="dns-list">
      <div className="list-head">
        <h3>Split DNS</h3>
        <InfoPopover label="Split DNS">
          <p>
            Domains your tailnet points at a particular nameserver. They resolve for app-tail and
            for nothing else on this machine.
          </p>
        </InfoPopover>
      </div>
      <ul>
        {routes.map((route) => (
          <li key={route.suffix}>
            <span className="mono">{route.suffix}</span>
            <span className="hint">
              {(route.resolvers ?? []).length > 0
                ? (route.resolvers ?? []).join(', ')
                : "answered by your tailnet's own resolver"}
            </span>
          </li>
        ))}
      </ul>
    </div>
  )
}

function TailnetRecords({ view }: { view: DNSView }) {
  const records = view.records ?? []
  if (records.length === 0) return null
  return (
    <div className="dns-list">
      <div className="list-head">
        <h3>Names your tailnet serves</h3>
        <InfoPopover label="Names your tailnet serves">
          <p>Records your tailnet answers for beyond its own devices.</p>
        </InfoPopover>
      </div>
      <ul>
        {records.map((record) => (
          <li key={`${record.name}/${record.type ?? 'A'}/${record.value}`}>
            <span className="mono">{record.name}</span>
            <span className="hint">
              {record.type ? `${record.type} ` : ''}
              {record.value}
            </span>
          </li>
        ))}
      </ul>
    </div>
  )
}

/** This machine's own resolver, beside the tailnet's. It is the half that answers "why
 *  doesn't my browser resolve foo.corp", and it is present even when there is nothing to
 *  show -- the reason is the answer, not a failed read. */
function ThisMachine({ view }: { view: DNSView }) {
  return (
    <div className="dns-list">
      <div className="list-head">
        <h3>This machine</h3>
        <InfoPopover label="This machine">
          <p>What every program other than app-tail resolves with.</p>
        </InfoPopover>
      </div>
      {view.machine ? (
        <ul>
          {(view.machine.nameservers ?? []).map((ns) => (
            <li key={ns} className="mono">
              {ns}
            </li>
          ))}
          {(view.machine.matchDomains ?? []).map((domain) => (
            <li key={`match-${domain}`}>
              <span className="mono">{domain}</span>
              <span className="hint">sent to your tailnet</span>
            </li>
          ))}
        </ul>
      ) : (
        <p className="dns-empty">{view.machineReason ?? 'Nothing is configured here.'}</p>
      )}
    </div>
  )
}

const USE_TAILNET_DNS = 'dns.useTailnet'

/** Which connections app-tail resolves names through, as a list of the networks that
 *  answer them. Whether one does is that connection's own setting, so the row links to the
 *  page holding it: this card reports what is answering, and changes nothing. */
function AnsweredBy({ tunnels }: { tunnels: readonly TunnelView[] }) {
  // Only the connections that carry the setting at all. A kind of network with no resolver
  // of its own is not answering names and is not failing to, either.
  const held = tunnels.filter((t) => USE_TAILNET_DNS in t.settings)
  if (held.length === 0) return null
  return (
    <div className="dns-list">
      <div className="list-head">
        <h3>Answered by</h3>
        <InfoPopover label="Answered by">
          <p>
            Which of your connections app-tail looks names up through. Each one carries the
            setting on its own page.
          </p>
        </InfoPopover>
      </div>
      <ul>
        {held.map((tunnel) => (
          <li key={tunnel.id}>
            <a href={`#/connections/${tunnel.type}/${tunnel.id}`}>{tunnel.name}</a>
            <span className="hint">
              {tunnel.settings[USE_TAILNET_DNS] === true
                ? "names are looked up through this network's DNS"
                : 'not used for name resolution'}
            </span>
          </li>
        ))}
      </ul>
    </div>
  )
}

export function DnsCard({
  view,
  form,
  tunnels,
}: {
  view: DNSView
  form: SettingsForm
  /** Every connection, so this card can say which of them answers names. */
  tunnels: readonly TunnelView[]
}) {
  const state = dnsState(view)

  return (
    <Panel
      // Named for the half of DNS it is about, because the card beside it is the other
      // half: one landmark called "DNS" inside a band called "DNS" is as confusing to
      // query as it is to hear read aloud.
      title="Tailnet DNS"
      wide
      status={{ tone: state.tone, label: state.label }}
      // The limits hold whether or not anything is resolving, and they read the same on
      // every machine. Inline they pushed the live answer below the fold; here they are
      // the first thing behind the button on the card they describe.
      info={
        <>
          <p>Which resolver app-tail uses for the names it looks up.</p>
          <InfoList items={view.capability.limits ?? []} />
        </>
      }
      controls={<ModuleSwitch form={form} switchKey="dns.enabled" />}
    >
      {!view.enabled ? (
        <ModuleOff>
          Off. Turn this on to resolve names with your tailnet's own DNS, including split-DNS
          domains.
        </ModuleOff>
      ) : (
        <>
          {view.capability.reason ? (
            <Notice tone={view.capability.available ? 'warn' : 'info'}>
              {view.capability.reason}
            </Notice>
          ) : null}

          {/* Named rather than flagged: this is the property people choose an exit node for,
          and it matters which device is doing the resolving. */}
          {view.exitNodeResolving ? (
            <Notice tone="info">
              Names outside your tailnet are being looked up by {view.exitNodeLabel}, not from this
              machine.
            </Notice>
          ) : null}

          <div className="dns-lists">
            <Names
              title="Your tailnet"
              hint="The nameservers your tailnet publishes."
              items={view.resolvers ?? []}
              empty="Your tailnet publishes no nameserver of its own."
            />
            <Names
              title="Search domains"
              hint="Suffixes your tailnet appends to a bare name."
              items={view.searchDomains ?? []}
              empty="Your tailnet publishes no search domain."
            />
            <ThisMachine view={view} />
          </div>

          <p className="hint">
            Device names {view.magicDNS ? 'resolve' : 'do not resolve'} through your tailnet.
          </p>

          <AnsweredBy tunnels={tunnels} />
          <SplitDNS view={view} />
          <TailnetRecords view={view} />

          {/* A failed read is the reason the module is degraded, so the agent puts it in
          both places. Printing it twice reads as two separate faults. */}
          {view.error && view.error !== view.capability.reason ? (
            <Notice tone="error">{view.error}</Notice>
          ) : null}
        </>
      )}
    </Panel>
  )
}
