// SPDX-License-Identifier: MIT

import { useCallback, useEffect } from 'react'

import { useAccess } from './auth'
import { Notice } from './components/primitives'
import { RestartButton, useReloadWhenBack } from './components/RestartButton'
import { useSettingsDraft } from './components/settings/useSettingsDraft'
import { SignedOut } from './components/SignedOut'
import { CONNECTIONS_LABELS } from './components/shell/ConnectionsNav'
import { DNS_LABELS } from './components/shell/DnsNav'
import { Shell } from './components/shell/Shell'
import { consecutiveFailuresBeforeBackoff } from './data/store'
import { usePolled, useStore } from './data/StoreProvider'
import {
  href,
  isConnectionsSection,
  isDnsSection,
  isSettingsSection,
  legacyHash,
  movedTo,
  type ConnectionsSectionId,
  type DnsSectionId,
  type Route,
  type SettingsSectionId,
} from './lib/router'
import { useAskedHash, useRoute } from './lib/useRoute'
import { AccessPage } from './pages/AccessPage'
import { ActivityPage } from './pages/ActivityPage'
import { ConnectionsPage } from './pages/ConnectionsPage'
import { DashboardPage } from './pages/DashboardPage'
import { PathsPage } from './pages/connections/PathsPage'
import { DnsPage } from './pages/DnsPage'
import { ForwardsPage } from './pages/ForwardsPage'
import { InspectionPage } from './pages/InspectionPage'
import { InternetPage } from './pages/InternetPage'
import { SecurityPage } from './pages/SecurityPage'
import { SettingsPage } from './pages/SettingsPage'

/** The name of the page a route lands on, which the top bar carries and the document is
 *  about. A section with pages of its own names the page rather than itself: "DNS" over
 *  a page holding one feature's card says less than the feature's own name. */
function titleOf(route: Route): string {
  switch (route.section) {
    case 'dashboard':
      return 'Dashboard'
    case 'connections': {
      // One connection's own name would be better, and it is data this component does
      // not hold: the page below reads the list, and naming the section is what the bar
      // can say without waiting on a poll.
      const section = connectionsSectionOf(route)
      return section === undefined ? 'Connections' : CONNECTIONS_LABELS[section]
    }
    case 'internet':
      return 'Internet'
    case 'dns': {
      const section = dnsSectionOf(route)
      return section === undefined ? 'DNS' : DNS_LABELS[section]
    }
    case 'inspection':
      return 'Traffic inspection'
    case 'security':
      return 'Security'
    case 'activity':
      return 'Activity'
    case 'settings':
      return 'Settings'
    default:
      return 'No such page'
  }
}

/** The page under Connections the address names: the landing page when it names none,
 *  and none at all on one connection's own page or a stale link. */
function connectionsSectionOf(route: Route): ConnectionsSectionId | undefined {
  const head = route.params[0]
  if (head === undefined) return 'networks'
  return isConnectionsSection(head) ? head : undefined
}

/** The page under DNS the address names, the resolver when it names none. */
function dnsSectionOf(route: Route): DnsSectionId | undefined {
  const head = route.params[0]
  if (head === undefined) return 'resolver'
  return isDnsSection(head) ? head : undefined
}

/** The page under Settings the address names, the app's own when it names none. */
function settingsSectionOf(route: Route): SettingsSectionId | undefined {
  const head = route.params[0]
  if (head === undefined) return 'application'
  return isSettingsSection(head) ? head : undefined
}

/** The save turned on a feature needing administrator rights, and the agent is restarting
 *  itself so Windows can ask for them. The page goes away with the process, so this waits
 *  for the new one and reloads onto it. */
function AdminRelaunchNotice() {
  useReloadWhenBack(true)
  return (
    <Notice tone="warn">
      Saved. app-tail is restarting so Windows can ask for administrator rights. Answer the
      prompt, and this page reloads once app-tail is back.
    </Notice>
  )
}

/** App is the dashboard while the agent accepts this page, and the screen saying how to
 *  sign back in once it does not. Swapping the whole tree also unmounts every poll, so a
 *  signed-out tab stops asking. */
export default function App() {
  const access = useAccess()
  return access.state === 'open' ? <Dashboard /> : <SignedOut access={access} />
}

function Dashboard() {
  const route = useRoute()
  const asked = useAskedHash()
  const store = useStore()
  const status = usePolled('status')

  // One form for the whole app. Every card writes through it, and each write sends only
  // the keys it changed, so two cards open at once cannot clobber each other.
  const form = useSettingsDraft()

  // The menu bar hands the dashboard a query string, which useRoute already reads for the
  // first paint. This is what puts the address it meant in the URL bar, so a reload or a
  // bookmark lands on the page rather than back at the top.
  useEffect(() => {
    if (window.location.hash !== '') return
    const legacy = legacyHash(window.location.search)
    if (legacy === undefined) return
    window.history.replaceState(null, '', legacy)
  }, [])

  // A page that moved is already rendering at its new address; this is what puts that
  // address in the URL bar, so re-bookmarking, reloading and copying the link all give
  // the page that exists rather than the one that used to.
  useEffect(() => {
    const moved = movedTo(asked)
    if (moved === undefined) return
    window.history.replaceState(null, '', moved)
  }, [asked])

  const refreshAll = useCallback(() => store.refreshAll(), [store])

  // Losing the agent is the failure users actually hit, so it gets a plain explanation
  // rather than a stack of per-page errors. An agent that stops while the tab is open
  // counts too: the last good answer is kept beside the error on purpose, so every card
  // keeps showing what was true before it died unless the failures are read here.
  const agentUnreachable =
    status.error !== undefined &&
    (status.data === undefined || status.failures >= consecutiveFailuresBeforeBackoff)

  return (
    <Shell
      route={route}
      title={titleOf(route)}
      version={status.data?.version}
      onRefresh={refreshAll}
      connectionsSection={connectionsSectionOf(route)}
      dnsSection={dnsSectionOf(route)}
      notices={
        <>
          {/* Everything the app has to say about itself, above whichever page is open. A
              restart owed, a setting stored but not in force, an agent that stopped --
              none of these belong to one page, and each of them outlives navigating. */}
          {agentUnreachable ? (
            <Notice tone="error">
              {status.error} — the agent may have stopped. This page keeps retrying.
            </Notice>
          ) : null}

          {/* The settings on every page are defaults rather than what this machine was
              set up with, and no card can say so: each one is reading its own value and
              finding it perfectly valid. */}
          {status.data?.configQuarantine ? (
            <Notice tone="error">
              The stored configuration could not be used, so app-tail started with the
              defaults: {status.data.configQuarantine.reason}. The document was kept at{' '}
              <code>{status.data.configQuarantine.path}</code> — fix it and run{' '}
              <code>app-tail config restore</code> to put it back.
            </Notice>
          ) : null}

          {/* The Application card keeps showing the configured address, which is the one the
              next start asks for again. This is what says where the agent actually is. */}
          {status.data?.dashboardMoved ? (
            <Notice tone="warn">
              The dashboard could not use <code>{status.data.dashboardMoved.configured}</code>,
              so it is on <code>{status.data.dashboardMoved.bound}</code> for now:{' '}
              {status.data.dashboardMoved.reason}. The configured address is unchanged and is
              tried again the next time the app starts.
            </Notice>
          ) : null}

          {form.error ? <Notice tone="error">{form.error}</Notice> : null}

          {form.nodeRestartPending ? (
            <Notice tone="warn">
              <div className="notice-row">
                <span>
                  Saved. Reconnect the tailnet node to apply these changes. Active forwards
                  are interrupted briefly and resume once it reconnects.
                </span>
                <button
                  className="btn small"
                  disabled={form.restarting}
                  onClick={() => void form.restartNode().then(refreshAll)}
                >
                  {form.restarting ? 'Restarting…' : 'Restart now'}
                </button>
              </div>
            </Notice>
          ) : null}

          {form.deferred.length > 0 ? (
            <Notice tone="warn">
              Saved, but not yet in force:
              <ul className="notice-list">
                {form.deferred.map((d) => (
                  <li key={d.key}>
                    {d.label} — {d.reason}.
                  </li>
                ))}
              </ul>
            </Notice>
          ) : null}

          {/* The value is stored and correct; nothing is waiting on the agent. What is
              missing is a start, so the notice offers one rather than describing a wait
              with no end. */}
          {form.appRestartPending ? (
            <Notice tone="warn">
              <div className="notice-row">
                <span>
                  Saved. app-tail reads this when it starts, so it applies the next time
                  app-tail starts.
                </span>
                <RestartButton />
              </div>
            </Notice>
          ) : null}

          {/* The rights are taken when the process starts and at no other moment, so the
              only way to act on this is to start again -- which is what the button does,
              and what puts the Windows prompt on screen. It also shows for a machine an
              earlier run left pointed at app-tail, which the same restart repairs, so the
              wording says nothing about the save being the cause. */}
          {form.adminRelaunchPending ? (
            <AdminRelaunchNotice />
          ) : form.adminRestartPending ? (
            <Notice tone="warn">
              <div className="notice-row">
                <span>
                  Saved. This needs administrator rights, which app-tail asks for when it
                  starts. Restart it to be asked now; until then it keeps running without
                  them.
                </span>
                <RestartButton />
              </div>
            </Notice>
          ) : null}

          {form.uiRelistenPending ? (
            <Notice tone="warn">
              Saved. The dashboard address changes only when the whole agent restarts; this
              page keeps serving on its current address until you restart it.
            </Notice>
          ) : null}
        </>
      }
    >
      <Page route={route} form={form} agentUnreachable={agentUnreachable} />
    </Shell>
  )
}

function Page({
  route,
  form,
  agentUnreachable,
}: {
  route: Route
  form: ReturnType<typeof useSettingsDraft>
  agentUnreachable: boolean
}) {
  switch (route.section) {
    case 'dashboard':
      return <DashboardPage form={form} />
    case 'connections':
      return <ConnectionsSection route={route} form={form} agentUnreachable={agentUnreachable} />
    case 'internet':
      return <InternetPage form={form} />
    case 'dns':
      return <DnsPage section={dnsSectionOf(route)} form={form} />
    case 'inspection':
      return <InspectionPage form={form} />
    case 'security':
      return <SecurityPage form={form} />
    case 'activity':
      return <ActivityPage form={form} />
    case 'settings':
      return <SettingsPage section={settingsSectionOf(route)} form={form} />

    default:
      return <NoSuchPage />
  }
}

/**
 * The pages under Connections. A page is looked for before a connection's own address
 * is, because the two share the first segment: `#/connections/paths` is a page and
 * `#/connections/wireguard/tn_x` is one network, and the router's tests keep the page
 * names and the kinds of connection disjoint.
 */
function ConnectionsSection({
  route,
  form,
  agentUnreachable,
}: {
  route: Route
  form: ReturnType<typeof useSettingsDraft>
  agentUnreachable: boolean
}) {
  const head = route.params[0]
  if (head === undefined) return <ConnectionsPage params={[]} form={form} />
  if (!isConnectionsSection(head)) {
    // A head that is not a page is a kind of connection, and a kind without an id after
    // it names nothing: a stale link says so rather than quietly showing the list.
    if (route.params[1] === undefined) return <NoSuchPage />
    return <ConnectionsPage params={route.params} form={form} />
  }
  switch (head) {
    case 'networks':
      return <ConnectionsPage params={[]} form={form} />
    case 'paths':
      return <PathsPage form={form} />
    case 'forwards':
      return <ForwardsPage form={form} agentUnreachable={agentUnreachable} />
    case 'grants':
    case 'proxies':
    case 'rules':
      return <AccessPage params={route.params} form={form} />
  }
}

/** An address that names no page says so. Quietly showing the dashboard instead is how a
 *  stale link survives long enough to be shared again. */
function NoSuchPage() {
  return (
    <section className="panel" aria-label="No such page">
      <div className="panel-body">
        <p>That address is not part of this dashboard.</p>
        <p>
          <a href={href('dashboard')}>Go to the dashboard</a>
        </p>
      </div>
    </section>
  )
}
