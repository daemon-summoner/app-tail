// SPDX-License-Identifier: MIT

import { act, fireEvent, within } from '@testing-library/react'
import { afterEach, describe, expect, it, onTestFinished, vi } from 'vitest'

import App from './App'
import { href } from './lib/router'
import { HEROES } from './pages/dashboard/heroes'
import {
  deferred,
  failWith,
  makeApprovalNeed,
  makeApprovals,
  makeAutoMap,
  makeDNS,
  makeDNSSystem,
  makeExitNode,
  makeForward,
  makeLock,
  makePrefs,
  makeRoutes,
  makeRouting,
  makeSettingsResponse,
  makeStatus,
  netFail,
  renderAgent,
  settle,
} from './test/agent'
import type { Status } from './api'

/** at points the document at an address before the app is rendered, which is what a link
 *  someone followed or a bookmark they opened looks like. */
function at(hash: string) {
  window.history.replaceState(null, '', `/${hash}`)
}

/** goTo navigates the way a click on a link in the rail does: the hash changes, and the
 *  app hears about it. */
async function goTo(hash: string) {
  act(() => {
    window.location.hash = hash
    window.dispatchEvent(new HashChangeEvent('hashchange'))
  })
  await settle()
}

afterEach(() => {
  window.history.replaceState(null, '', '/')
})

describe('the shell', () => {
  it('offers every section once, as a link', async () => {
    const { getByRole } = await renderAgent(<App />)

    const rail = getByRole('navigation', { name: 'Sections' })
    expect(within(rail).getAllByRole('link').map((a) => a.textContent)).toEqual([
      'Dashboard',
      'Connections',
      'Internet',
      'DNS',
      'Inspection',
      'Security',
      'Activity',
      'Settings',
    ])
  })

  // The highlight is a colour, and a colour is not a signal a screen reader has. Both
  // marks are set from the same answer, so neither can drift from the other.
  it('marks the section the reader is on', async () => {
    at(href('connections', 'forwards'))
    const { getByRole } = await renderAgent(<App />)

    const rail = getByRole('navigation', { name: 'Sections' })
    expect(within(rail).getByRole('link', { current: 'page' })).toHaveTextContent('Connections')
  })

  it.each([
    ['#/', 'Dashboard'],
    [href('connections'), 'Networks'],
    [href('connections', 'forwards'), 'Port forwards'],
    [href('connections', 'tailscale', 'tn_primary'), 'Connections'],
    [href('internet'), 'Internet'],
    [href('dns'), 'System resolver'],
    [href('dns', 'blocklist'), 'Blocking'],
    [href('inspection'), 'Traffic inspection'],
    [href('security'), 'Security'],
    [href('settings'), 'Settings'],
    [href('settings', 'application'), 'Settings'],
  ])('names the page at %s in the bar', async (hash, title) => {
    at(hash)
    const { getByRole } = await renderAgent(<App />)

    expect(getByRole('heading', { level: 1 })).toHaveTextContent(title)
  })

  // The second column is the only navigation inside a section, so it exists exactly where
  // there is something to navigate. A section with one page, or none, has no column: an
  // empty rail beside Security or Settings would promise pages that are not there.
  it('shows the connections column only under connections', async () => {
    at(href('security'))
    const { queryByRole } = await renderAgent(<App />)
    expect(queryByRole('navigation', { name: 'Connections sections' })).not.toBeInTheDocument()

    await goTo(href('connections', 'proxies'))

    expect(queryByRole('navigation', { name: 'Connections sections' })).toBeInTheDocument()

    await goTo(href('settings'))

    expect(queryByRole('navigation', { name: 'Connections sections' })).not.toBeInTheDocument()
    expect(queryByRole('navigation', { name: 'DNS sections' })).not.toBeInTheDocument()
  })

  // The bare address and the landing page's own name are one page, so the column's link
  // to it is the bare address: the two ways of reaching it are one entry in history, and
  // the link is marked current from either.
  it('marks the landing page current from the bare address', async () => {
    at(href('connections'))
    const { getByRole } = await renderAgent(<App />)

    const column = getByRole('navigation', { name: 'Connections sections' })
    const here = within(column).getByRole('link', { current: 'page' })
    expect(here).toHaveTextContent('Networks')
    expect(here).toHaveAttribute('href', href('connections'))
  })

  // The rail's own Settings link is the bare address, so it has to land on a page, and
  // the menu bar's link names that page, so both addresses are one page.
  it.each([href('settings'), href('settings', 'application')])(
    "opens the app's own settings at %s",
    async (hash) => {
      at(hash)
      const { getByRole, queryByRole } = await renderAgent(<App />)

      expect(getByRole('region', { name: 'This app' })).toBeInTheDocument()
      expect(queryByRole('region', { name: 'Security' })).not.toBeInTheDocument()
    },
  )

  // Security is a section of the rail, so its link is marked current there and the page
  // has no column of its own.
  it('opens security from the rail', async () => {
    at(href('security'))
    const { getByRole, queryByRole } = await renderAgent(<App />)

    expect(getByRole('region', { name: 'Security' })).toBeInTheDocument()
    const rail = getByRole('navigation', { name: 'Sections' })
    expect(within(rail).getByRole('link', { current: 'page' })).toHaveTextContent('Security')
    expect(queryByRole('region', { name: 'This app' })).not.toBeInTheDocument()
  })

  it('shows the DNS column with the resolver first', async () => {
    at(href('dns', 'names'))
    const { getByRole } = await renderAgent(<App />)

    const column = getByRole('navigation', { name: 'DNS sections' })
    expect(within(column).getAllByRole('link').map((a) => a.textContent)).toEqual([
      'System resolver',
      'Blocking',
      'Names',
    ])
    expect(within(column).getByRole('link', { current: 'page' })).toHaveTextContent('Names')
  })

  // Every route is in the hash, so the browser never asks the agent for a second document.
  // A page that reloaded would lose the polls, the form and the notices with it.
  it('swaps the page when the address changes, without reloading', async () => {
    const { queryByLabelText } = await renderAgent(<App />, {
      'GET /api/automap': makeAutoMap(),
    })
    expect(queryByLabelText('How this machine reaches the tailnet')).toBeInTheDocument()

    await goTo(href('connections', 'forwards'))

    expect(queryByLabelText('Port forwards')).toBeInTheDocument()
    expect(queryByLabelText('How this machine reaches the tailnet')).not.toBeInTheDocument()
  })

  // A stale link is the usual way anyone reaches an address that names nothing. Showing
  // the dashboard instead is how such a link survives long enough to be shared again.
  it('says so when the address names no page', async () => {
    at('#/nowhere')
    const { getByRole } = await renderAgent(<App />)

    expect(getByRole('region', { name: 'No such page' })).toHaveTextContent(
      'not part of this dashboard',
    )
    expect(getByRole('heading', { level: 1 })).toHaveTextContent('No such page')
  })

  // Under Connections a stale link can also name a kind of connection with no connection
  // after it, which is nothing at all rather than the list of every network.
  it('says so when the address under connections names no page and no connection', async () => {
    at(href('connections', 'nowhere'))
    const { getByRole, queryByRole } = await renderAgent(<App />)

    expect(getByRole('region', { name: 'No such page' })).toBeInTheDocument()
    expect(queryByRole('region', { name: 'Tailscale' })).not.toBeInTheDocument()
  })

  it('says so when the address names no settings section', async () => {
    at(href('settings', 'nowhere'))
    const { getByRole } = await renderAgent(<App />)

    expect(getByRole('region', { name: 'No such section' })).toHaveTextContent(
      'not part of this dashboard',
    )
  })

  // The DNS column is still the way out of a stale DNS link, so it stays drawn with
  // nothing marked current: the reader is under DNS and on none of its pages.
  it('says so when the address names no DNS section, and marks no page current', async () => {
    at(href('dns', 'nowhere'))
    const { getByRole } = await renderAgent(<App />)

    expect(getByRole('region', { name: 'No such section' })).toHaveTextContent(
      'not part of this dashboard',
    )
    expect(getByRole('heading', { level: 1 })).toHaveTextContent('DNS')
    const column = getByRole('navigation', { name: 'DNS sections' })
    expect(within(column).queryByRole('link', { current: 'page' })).not.toBeInTheDocument()
  })

  // The browser's back button is the one navigation the rail does not make, and the
  // address it restores arrives the same way a click does. A router that only heard its
  // own links would leave the old page on screen under the restored address.
  it('follows the back and forward buttons', async () => {
    // The document traverses its history on later tasks, queued behind the ones the hash
    // assignments above left pending, so the event the router hears arrives after two
    // macrotasks rather than after the microtasks settle drains.
    const traverse = (step: () => void) =>
      act(async () => {
        step()
        for (let i = 0; i < 2; i += 1) {
          await new Promise((resolve) => setTimeout(resolve, 0))
        }
      })
    const { queryByLabelText, getByRole } = await renderAgent(<App />, {
      'GET /api/automap': makeAutoMap(),
    })
    await goTo(href('connections', 'forwards'))
    await goTo(href('dns'))
    expect(getByRole('heading', { level: 1 })).toHaveTextContent('System resolver')

    await traverse(() => window.history.back())
    expect(window.location.hash).toBe(href('connections', 'forwards'))
    expect(queryByLabelText('Port forwards')).toBeInTheDocument()
    expect(getByRole('heading', { level: 1 })).toHaveTextContent('Port forwards')

    await traverse(() => window.history.forward())
    expect(window.location.hash).toBe(href('dns'))
    expect(getByRole('heading', { level: 1 })).toHaveTextContent('System resolver')
    expect(queryByLabelText('Port forwards')).not.toBeInTheDocument()
  })

  // Every mutation the dashboard makes ends in a refresh, and the bar is where a reader
  // asks for one by hand.
  it('re-reads everything on screen when the bar is used', async () => {
    const { agent, getByRole } = await renderAgent(<App />)
    const before = agent.countOf('GET /api/status')

    fireEvent.click(getByRole('button', { name: 'Refresh' }))
    await settle()

    expect(agent.countOf('GET /api/status')).toBeGreaterThan(before)
  })
})

// The menu bar's entries can only launch a browser, so the query string is the entire
// handoff. It predates these routes and its URLs are pinned by the tray's own tests, so
// the dashboard is what translates them.
describe('the page the menu bar asks for', () => {
  it('opens the app settings, and puts that address in the bar', async () => {
    window.history.replaceState(null, '', '/?settings=1')
    const { getByRole } = await renderAgent(<App />)

    expect(getByRole('region', { name: 'This app' })).toBeInTheDocument()
    expect(window.location.hash).toBe(href('settings', 'application'))
  })

  it('opens the DNS page', async () => {
    window.history.replaceState(null, '', '/?section=dns')
    const { getByLabelText } = await renderAgent(<App />, {
      'GET /api/dns': makeDNS({ system: makeDNSSystem() }),
    })

    expect(getByLabelText('System resolver')).toBeInTheDocument()
    expect(window.location.hash).toBe(href('dns'))
  })

  it('lands on the dashboard on a plain load', async () => {
    const { getByRole } = await renderAgent(<App />)

    expect(getByRole('heading', { level: 1 })).toHaveTextContent('Dashboard')
    expect(window.location.hash).toBe('')
  })
})

describe('when the agent cannot be reached', () => {
  // Losing the agent is the failure users actually hit -- they quit it, or it crashed. A
  // bare per-panel error reads as a bug in the dashboard; naming the agent and saying the
  // page keeps retrying is the difference between "restart it" and "file an issue".
  it('explains that the agent may have stopped and that the page keeps retrying', async () => {
    const { getByText } = await renderAgent(<App />, { 'GET /api/status': netFail() })

    expect(getByText(/the agent may have stopped/)).toHaveTextContent(
      'cannot reach the app-tail agent',
    )
    expect(getByText(/the agent may have stopped/)).toHaveTextContent('keeps retrying')
  })

  // Every page polls the same dead agent, so without the suppression the user gets a stack
  // of notices all saying the same thing.
  it('gives one explanation rather than one per panel', async () => {
    at(href('connections', 'forwards'))
    const { container } = await renderAgent(<App />, {
      'GET /api/status': netFail(),
      'GET /api/forwards': netFail(),
    })

    expect(container.querySelectorAll('.notice.error')).toHaveLength(1)
  })

  // The reverse case: the agent is alive and only the forwards call failed, so that error
  // is the user's only clue and must not be swallowed.
  it('still shows a forwards failure while the agent itself answers', async () => {
    at(href('connections', 'forwards'))
    const { container, queryByText } = await renderAgent(<App />, {
      'GET /api/forwards': netFail(),
    })

    const notices = container.querySelectorAll('.notice.error')
    expect(notices).toHaveLength(1)
    expect(notices[0]).toHaveTextContent('cannot reach the app-tail agent')
    // The suppressed notice is the whole-agent one, not this.
    expect(queryByText(/the agent may have stopped/)).not.toBeInTheDocument()
  })

  // The agent people lose is one that was answering a minute ago: they quit it, or it
  // crashed while the tab stayed open. The last good answer is kept on purpose so a card
  // does not blank out during a restart, so a screen full of values that were true a
  // minute ago is exactly what a dead agent looks like unless this notice says otherwise.
  it('explains it after the agent stops answering a page that had loaded', async () => {
    const { agent, getByRole, queryByText, getByText } = await renderAgent(<App />)
    expect(queryByText(/the agent may have stopped/)).not.toBeInTheDocument()

    agent.set('GET /api/status', netFail())
    // One failed poll is a restart. The notice is owed once the failures stop reading as
    // one, which is the same count the store slows its polling down at.
    for (let i = 0; i < 3; i += 1) {
      fireEvent.click(getByRole('button', { name: 'Refresh' }))
      await settle()
    }

    expect(getByText(/the agent may have stopped/)).toHaveTextContent(
      'cannot reach the app-tail agent',
    )
  })

  // A poll that failed once while the agent is being restarted must not throw an error
  // across a dashboard that is about to keep working.
  it('stays quiet through a single failed poll', async () => {
    const { agent, getByRole, container } = await renderAgent(<App />)

    agent.set('GET /api/status', netFail())
    fireEvent.click(getByRole('button', { name: 'Refresh' }))
    await settle()

    expect(container.querySelectorAll('.notice.error')).toHaveLength(0)
  })
})

describe('when the agent does not accept the session', () => {
  // Every request is refused, so the frame and its pages would be a stack of identical
  // errors. The one thing the user can do is open the dashboard again.
  it('replaces the dashboard with the way to sign back in', async () => {
    const { getByRole, queryByRole } = await renderAgent(<App />, {}, { unauthorized: true })

    const screen = getByRole('region', { name: 'Open the dashboard again' })
    expect(within(screen).getByRole('heading', { name: 'Open the dashboard again' })).toBeVisible()
    expect(screen).toHaveTextContent('app-tail dashboard')
    expect(screen).toHaveTextContent('app-tail menu')
    expect(queryByRole('navigation', { name: 'Sections' })).not.toBeInTheDocument()
  })

  // The pages stop polling once they are gone, rather than asking a refusing agent again
  // every few seconds for as long as the tab stays open.
  it('stops asking the agent once it is signed out', async () => {
    vi.useFakeTimers()
    onTestFinished(() => {
      vi.useRealTimers()
    })
    const { agent, getByRole } = await renderAgent(<App />, {}, { unauthorized: true })
    getByRole('region', { name: 'Open the dashboard again' })
    const asked = agent.calls.length

    // Longer than the slowest poll's longest backoff.
    await act(async () => {
      await vi.advanceTimersByTimeAsync(120_000)
    })

    expect(agent.calls.length).toBe(asked)
  })

  it('says it is the browser storage when the session cannot be kept', async () => {
    const { getByRole, queryByRole } = await renderAgent(<App />, {}, { storageRefused: true })

    const screen = getByRole('region', { name: 'This browser will not keep the sign-in' })
    expect(screen).toHaveTextContent('the browser is blocking site data')
    expect(queryByRole('navigation', { name: 'Sections' })).not.toBeInTheDocument()
  })
})

describe('when the stored configuration could not be used', () => {
  // Every card reads a valid value and has no way to know it is a default rather than what
  // this machine was set up with. This notice is the only thing on any screen that says the
  // settings in front of the reader are not theirs.
  it('says the app started on the defaults and where the document was kept', async () => {
    const { getByText } = await renderAgent(<App />, {
      'GET /api/status': makeStatus({
        configQuarantine: {
          path: '/state/config.json.unusable-20240101-000000',
          reason: 'config.json could not be read as JSON',
          at: '2024-01-01T00:00:00Z',
        },
      }),
    })

    const notice = getByText(/started with the\s+defaults/)
    expect(notice).toHaveTextContent('could not be read as JSON')
    expect(notice).toHaveTextContent('/state/config.json.unusable-20240101-000000')
    expect(notice).toHaveTextContent('app-tail config restore')
  })

  // A notice on every screen of every normal run is a notice nobody reads on the run that
  // matters.
  it('says nothing on a run whose configuration loaded', async () => {
    const { container } = await renderAgent(<App />)

    expect(container.querySelectorAll('.notice.error')).toHaveLength(0)
  })
})

// The root helper refuses network changes nobody approved, so a switch that was turned on
// sits there doing nothing until an administrator says yes. The dashboard is where that is
// asked, and the feature's own page is where somebody looks when the switch seems broken.
describe('changes waiting for an administrator', () => {
  const INTERCEPT = 'open encrypted connections and read what they carry'
  const FULL_TUNNEL = "carry all of this machine's internet traffic through app-tail"

  function waiting(): Status {
    return makeStatus({
      approvals: makeApprovals({
        needs: [
          makeApprovalNeed({ kind: 'full-tunnel', reason: FULL_TUNNEL, features: ['interface'] }),
          makeApprovalNeed({
            kind: 'tls-interception',
            reason: INTERCEPT,
            features: ['tls-interception'],
          }),
        ],
        command: 'sudo app-tail tun grant --full-tunnel --tls-interception',
      }),
    })
  }

  it('asks on the dashboard, and reads the status again once approved', async () => {
    const { agent, getByRole, queryByRole } = await renderAgent(<App />, {
      'GET /api/status': waiting(),
      'POST /api/tun/approve': { needs: [], command: '' },
    })

    const banner = getByRole('region', { name: 'Needs your approval' })
    expect(banner).toHaveTextContent(FULL_TUNNEL)
    expect(banner).toHaveTextContent(INTERCEPT)

    agent.set('GET /api/status', makeStatus())
    const asked = agent.countOf('GET /api/status')
    fireEvent.click(within(banner).getByRole('button', { name: 'Approve…' }))
    await settle(4)

    expect(agent.countOf('POST /api/tun/approve')).toBe(1)
    expect(agent.countOf('GET /api/status')).toBeGreaterThan(asked)
    expect(queryByRole('region', { name: 'Needs your approval' })).not.toBeInTheDocument()
  })

  it('asks nothing on a dashboard with nothing waiting', async () => {
    const { queryByRole } = await renderAgent(<App />)

    expect(queryByRole('region', { name: 'Needs your approval' })).not.toBeInTheDocument()
  })

  it('asks on the inspection page only for what inspection is waiting on', async () => {
    at(href('inspection'))
    const { getByRole } = await renderAgent(<App />, { 'GET /api/status': waiting() })

    const banner = getByRole('region', { name: 'Needs your approval' })
    const [own] = within(banner).getAllByRole('list')
    expect(within(own!).getAllByRole('listitem').map((li) => li.textContent)).toEqual([INTERCEPT])
  })

  it('asks nothing on the inspection page when only other features are waiting', async () => {
    at(href('inspection'))
    const { queryByRole } = await renderAgent(<App />, {
      'GET /api/status': makeStatus({ approvals: makeApprovals() }),
    })

    expect(queryByRole('region', { name: 'Needs your approval' })).not.toBeInTheDocument()
  })
})

describe('when the dashboard could not have its configured address', () => {
  // The Application card keeps showing the configured address, so nothing else on any
  // screen says the app is answering somewhere else for this run.
  it('names the address it wanted, the one it is on, and that the setting stands', async () => {
    const { getByText } = await renderAgent(<App />, {
      'GET /api/status': makeStatus({
        dashboardMoved: {
          configured: '127.0.0.1:8377',
          bound: '127.0.0.1:52341',
          reason: 'listen tcp 127.0.0.1:8377: bind: address already in use',
        },
      }),
    })

    const notice = getByText(/could not use/).closest('.notice')
    expect(notice).not.toBeNull()
    expect(notice).toHaveTextContent('127.0.0.1:8377')
    expect(notice).toHaveTextContent('127.0.0.1:52341')
    expect(notice).toHaveTextContent('address already in use')
    expect(notice).toHaveTextContent(/configured address is unchanged/)
  })

  it('says nothing on a run that bound the address it was asked for', async () => {
    const { container } = await renderAgent(<App />)

    expect(container.querySelectorAll('.notice.warn')).toHaveLength(0)
  })
})

// The rights are taken when the process starts, so a setting that needs them is stored
// and inert until app-tail is started again. Without the offer the switch reads as broken:
// it stays where it was put and nothing on this machine changes.
describe('a setting that needs administrator rights', () => {
  it('says the rights are asked for at start, and offers a restart', async () => {
    at(href('settings', 'application'))
    const { getByLabelText, getByText } = await renderAgent(<App />, {
      'PUT /api/settings': makeSettingsResponse({ showTray: false, adminRestart: true }),
    })

    fireEvent.click(getByLabelText('Show tray icon'))
    await settle()

    const notice = getByText(/asks for when it starts/).closest('.notice')
    expect(notice).not.toBeNull()
    expect(
      within(notice as HTMLElement).getByRole('button', { name: 'Restart app-tail' }),
    ).toBeInTheDocument()
  })

  it('says app-tail is restarting when the save restarted it to be asked', async () => {
    at(href('settings', 'application'))
    const { getByLabelText, getByText, queryByText } = await renderAgent(<App />, {
      'PUT /api/settings': makeSettingsResponse({
        showTray: false,
        adminRestart: true,
        adminRelaunch: true,
      }),
    })

    fireEvent.click(getByLabelText('Show tray icon'))
    await settle()

    expect(getByText(/restarting so Windows can ask for administrator rights/)).toBeInTheDocument()
    // The process is already on its way out, so offering to restart it again is a button
    // that does nothing but race the restart in progress.
    expect(queryByText(/Restart it to be asked now/)).toBeNull()
  })

  it('says nothing about rights for a change that needs none', async () => {
    at(href('settings', 'application'))
    const { getByLabelText, queryByText } = await renderAgent(<App />, {
      'PUT /api/settings': makeSettingsResponse({ showTray: false }),
    })

    fireEvent.click(getByLabelText('Show tray icon'))
    await settle()

    expect(queryByText(/asks for when it starts/)).toBeNull()
  })
})

// The tray icon is built once, when the process starts, so the switch stores a value that
// nothing acts on until the next start. Without a notice the switch reads as broken: it
// stays where it was put and the icon it names does not move.
describe('a setting the app only reads when it starts', () => {
  it('says the change waits for the next start, and offers one', async () => {
    at(href('settings', 'application'))
    const { getByLabelText, getByText } = await renderAgent(<App />, {
      'PUT /api/settings': makeSettingsResponse({ showTray: false, appRestart: true }),
    })

    fireEvent.click(getByLabelText('Show tray icon'))
    await settle()

    // The restart sits in the notice itself: a sentence saying a change is waiting, with
    // the way to apply it somewhere else on the page, is a sentence that reads as a dead
    // end.
    const notice = getByText(/next time app-tail starts/).closest('.notice')
    expect(notice).not.toBeNull()
    expect(
      within(notice as HTMLElement).getByRole('button', { name: 'Restart app-tail' }),
    ).toBeInTheDocument()
  })

  it('says nothing for a change that is in force at once', async () => {
    at(href('settings', 'application'))
    const { getByLabelText, queryByText } = await renderAgent(<App />, {
      'PUT /api/settings': makeSettingsResponse({ showTray: false }),
    })

    fireEvent.click(getByLabelText('Show tray icon'))
    await settle()

    expect(queryByText(/next time app-tail starts/)).not.toBeInTheDocument()
  })
})

// The identity settings are read when the tailnet node is built, so a save that changes
// one is stored and not yet in force. The notice is the only thing that says so, and its
// button is the only way to put the change in force without restarting the whole app.
describe('a setting that needs the tailnet node reconnected', () => {
  async function saveOne(routes: Record<string, unknown>) {
    at(href('settings', 'application'))
    const view = await renderAgent(<App />, {
      'PUT /api/settings': makeSettingsResponse({ showTray: false, nodeRestart: true }),
      ...routes,
    })
    fireEvent.click(view.getByLabelText('Show tray icon'))
    await settle()
    return view
  }

  it('offers the reconnect, holds the button while it runs, then re-reads the pages', async () => {
    const restart = deferred<{ backendState: string }>()
    const view = await saveOne({ 'POST /api/restart': () => restart.promise })
    const { agent, getByText, getByRole, queryByText } = view

    const notice = getByText(/Reconnect the tailnet node/).closest('.notice')
    expect(notice).not.toBeNull()
    const button = within(notice as HTMLElement).getByRole('button', { name: 'Restart now' })
    const polled = agent.countOf('GET /api/status')

    fireEvent.click(button)
    await settle()

    // Held until the agent answers: a second click while the node is being rebuilt would
    // queue a second rebuild.
    expect(agent.countOf('POST /api/restart')).toBe(1)
    expect(getByRole('button', { name: 'Restarting…' })).toBeDisabled()

    restart.resolve({ backendState: 'Running' })
    await settle()
    await settle()

    expect(queryByText(/Reconnect the tailnet node/)).not.toBeInTheDocument()
    expect(agent.countOf('GET /api/status')).toBeGreaterThan(polled)
  })

  it('keeps the offer and says why when the reconnect is refused', async () => {
    const { getByText, getByRole } = await saveOne({
      'POST /api/restart': failWith(503, 'the tailnet node is not running'),
    })

    fireEvent.click(getByRole('button', { name: 'Restart now' }))
    await settle()

    expect(getByText('the tailnet node is not running').closest('.notice')).toHaveClass('error')
    // Nothing was applied, so the change is still waiting and the button is usable again.
    expect(getByText(/Reconnect the tailnet node/)).toBeInTheDocument()
    expect(getByRole('button', { name: 'Restart now' })).toBeEnabled()
  })

  it('says nothing about the node for a change that is in force at once', async () => {
    at(href('settings', 'application'))
    const { getByLabelText, queryByText } = await renderAgent(<App />, {
      'PUT /api/settings': makeSettingsResponse({ showTray: false }),
    })

    fireEvent.click(getByLabelText('Show tray icon'))
    await settle()

    expect(queryByText(/Reconnect the tailnet node/)).not.toBeInTheDocument()
  })
})

describe('what the app says above the page after a save', () => {
  async function flip(routes: Record<string, unknown>) {
    at(href('settings', 'application'))
    const view = await renderAgent(<App />, routes)
    fireEvent.click(view.getByLabelText('Show tray icon'))
    await settle()
    return view
  }

  // A switch applies on the click. When the agent refuses it, the switch has to go back
  // where it was, and the refusal has to be said somewhere the reader is looking, which is
  // above the page rather than inside a card that may be folded.
  it('shows a refused save as an error and puts the switch back', async () => {
    const { getByText, getByLabelText } = await flip({
      'PUT /api/settings': failWith(400, 'showTray: the tray cannot be hidden on this platform'),
    })

    expect(
      getByText('showTray: the tray cannot be hidden on this platform').closest('.notice'),
    ).toHaveClass('error')
    expect(getByLabelText('Show tray icon')).toBeChecked()
  })

  it('lists each setting that was stored but is not yet in force, with its reason', async () => {
    const { getByText } = await flip({
      'PUT /api/settings': makeSettingsResponse({
        showTray: false,
        deferred: [
          { key: 'systemDns.enabled', label: 'Machine resolver', reason: 'no connection is up' },
          { key: 'proxy.enabled', label: 'Proxy', reason: 'the port is taken' },
        ],
      }),
    })

    const notice = getByText(/Saved, but not yet in force/).closest('.notice')
    expect(notice).not.toBeNull()
    expect(
      within(notice as HTMLElement)
        .getAllByRole('listitem')
        .map((li) => li.textContent),
    ).toEqual(['Machine resolver — no connection is up.', 'Proxy — the port is taken.'])
  })

  it('says the dashboard address only moves when the whole agent restarts', async () => {
    const { getByText } = await flip({
      'PUT /api/settings': makeSettingsResponse({ showTray: false, uiRelisten: true }),
    })

    expect(getByText(/keeps serving on its current address/).closest('.notice')).toHaveClass(
      'warn',
    )
  })

  it('shows none of those for a save that is in force at once', async () => {
    const { queryByText, container } = await flip({
      'PUT /api/settings': makeSettingsResponse({ showTray: false }),
    })

    expect(queryByText(/Saved, but not yet in force/)).not.toBeInTheDocument()
    expect(queryByText(/keeps serving on its current address/)).not.toBeInTheDocument()
    expect(container.querySelector('.notice.error')).toBeNull()
  })
})

describe('before the first status lands', () => {
  it('says it is connecting rather than showing an empty card', async () => {
    const pending = deferred<Status>()
    const { container, queryByLabelText } = await renderAgent(<App />, {
      'GET /api/status': () => pending.promise,
    })

    expect(container.querySelector('.status.pending')).toHaveTextContent('Connecting to the agent')
    expect(queryByLabelText('Tailnet connection')).not.toBeInTheDocument()

    pending.resolve(makeStatus())
    await settle()

    expect(queryByLabelText('Tailnet connection')).toBeInTheDocument()
  })

  // The heroes are drawn from the settings schema, so until it lands they are outlines
  // with their names on, in the places they will occupy.
  it('draws the hero deck as outlines until the settings arrive', async () => {
    const pending = deferred<unknown>()
    const { container, queryByRole } = await renderAgent(<App />, {
      'GET /api/settings': () => pending.promise,
    })

    const deck = container.querySelector('.hero-deck[aria-busy="true"]')
    expect(deck).not.toBeNull()
    expect(deck?.querySelectorAll('.skeleton').length).toBeGreaterThan(0)
    expect(queryByRole('link', { name: 'Internet settings' })).not.toBeInTheDocument()

    pending.resolve(makeSettingsResponse({}))
    await settle()

    expect(container.querySelector('.hero-deck[aria-busy="true"]')).toBeNull()
    expect(queryByRole('link', { name: 'Internet settings' })).toBeInTheDocument()
  })

  it('says why the heroes are missing when the settings cannot be read', async () => {
    const { container } = await renderAgent(<App />, {
      'GET /api/settings': failWith(503, 'the settings store is locked'),
    })

    expect(container.querySelector('.hero-deck')).toBeNull()
    expect(container.querySelector('.notice.error')).toHaveTextContent('the settings store is locked')
  })

  // nodeRunning defaults to false while status is unknown. Defaulting the other way would
  // tell the user their forwards are fine when nothing has confirmed the tailnet is up.
  it('treats the tailnet as down until the agent says otherwise', async () => {
    at(href('connections', 'forwards'))
    const pending = deferred<Status>()
    const { getByLabelText } = await renderAgent(<App />, {
      'GET /api/status': () => pending.promise,
      'GET /api/forwards': { forwards: [makeForward({ name: 'ssh', enabled: true, state: '' })] },
    })

    expect(getByLabelText('Port forwards')).toHaveTextContent('waiting for the tailnet')
  })
})

// Each page holds the cards that answer its own question. What is asserted here is only
// that the card is on the page the nav sends someone to -- what each card says is its own
// suite's subject.
describe('what each page holds', () => {
  it('puts the connection, the reach tiles and the graph on the dashboard', async () => {
    const { getByLabelText } = await renderAgent(<App />)

    expect(getByLabelText('Tailnet connection')).toBeInTheDocument()
    expect(getByLabelText('How this machine reaches the tailnet')).toBeInTheDocument()
    expect(getByLabelText('Live traffic')).toBeInTheDocument()
  })

  it('puts the forwards table and the automatic ports together', async () => {
    at(href('connections', 'forwards'))
    const { getByLabelText } = await renderAgent(<App />, {
      'GET /api/automap': makeAutoMap(),
    })

    expect(getByLabelText('Port forwards')).toBeInTheDocument()
    expect(getByLabelText('Automatic ports')).toBeInTheDocument()
  })

  // Two cards about two different things: one changes this machine, the other changes only
  // app-tail. They are both about name resolution, so they share a section, and each is
  // its own page so that the machine-wide one -- which works on a machine that is not
  // signed in to a tailnet at all -- is what the section opens on.
  it('opens DNS on the machine resolver and keeps the tailnet one on its own page', async () => {
    at(href('dns'))
    const resolver = await renderAgent(<App />, {
      'GET /api/dns': makeDNS({ system: makeDNSSystem() }),
    })
    expect(resolver.getByLabelText('System resolver')).toBeInTheDocument()
    expect(resolver.queryByLabelText('Tailnet DNS')).not.toBeInTheDocument()
    resolver.unmount()

    at(href('dns', 'names'))
    const names = await renderAgent(<App />, {
      'GET /api/dns': makeDNS({ system: makeDNSSystem() }),
    })
    expect(names.getByLabelText('Tailnet DNS')).toBeInTheDocument()
    expect(names.queryByLabelText('System resolver')).not.toBeInTheDocument()
  })

  // An agent older than this feature sends no system half at all, and a card rendered from
  // nothing would claim a machine-wide resolver that this build cannot switch.
  it('leaves the machine resolver out when the agent does not report one', async () => {
    at(href('dns'))
    const { getByLabelText, queryByLabelText } = await renderAgent(<App />, {
      'GET /api/dns': makeDNS(),
    })

    expect(queryByLabelText('System resolver')).not.toBeInTheDocument()
    expect(getByLabelText('No system resolver')).toHaveTextContent(/does not carry/)
  })

  // The rules are exceptions to where internet traffic leaves, so they belong on the page
  // that holds the setting they except -- and the served rules have to reach the card, or it
  // is a table of nothing beside a setting it claims to override.
  it('puts the per-destination rules under the internet traffic setting', async () => {
    at(href('internet'))
    const { getByRole, getByLabelText } = await renderAgent(<App />, {
      'GET /api/routing': makeRouting({
        rules: [{ id: 'rt_1', action: 'via', tunnel: 'tn_office', host: '*.corp.example' }],
        describe: ['rule 1 sends *.corp.example through Office'],
      }),
    })

    expect(getByRole('region', { name: 'Per-destination rules' })).toBeInTheDocument()
    expect(getByLabelText('Rule 1: destination')).toHaveValue('*.corp.example')
  })

  it.each([
    ['security', href('security'), 'Security'],
    ['application', href('settings', 'application'), 'This app'],
  ])('puts the %s card on its own page', async (_section, hash, label) => {
    at(hash)
    const { getByRole } = await renderAgent(<App />)

    expect(getByRole('region', { name: label })).toBeInTheDocument()
  })

  // The pages under Connections are ordered so a reader never has to reach the last, which
  // only holds if each address actually lands on the page it names. A page and one
  // connection's own address share the first segment, so the last row pins that a kind of
  // connection is still reached as one.
  it.each([
    ['networks', href('connections', 'networks'), 'Tailscale'],
    ['paths', href('connections', 'paths'), 'How app-tail runs here'],
    ['forwards', href('connections', 'forwards'), 'Port forwards'],
    ['grants', href('connections', 'grants'), 'What can reach what'],
    ['proxies', href('connections', 'proxies'), 'Proxies'],
    ['rules', href('connections', 'rules', 'px_default'), 'What Default may reach'],
    ['one connection', href('connections', 'tailscale', 'tn_primary'), 'Tailnet'],
  ])('puts the %s page under connections', async (_section, hash, label) => {
    at(hash)
    const { getByRole } = await renderAgent(<App />)

    expect(getByRole('region', { name: label })).toBeInTheDocument()
  })

  // The dashboard is the hub: every feature somebody comes to flip is a card here, and
  // every card's gear opens the page with the rest of that feature. A hero missing from the
  // page, or a gear pointing elsewhere, is a feature reachable only by somebody who already
  // knows the address.
  it('puts every hero on the dashboard, each with its gear to its own page', async () => {
    at('#/')
    const { getByRole } = await renderAgent(<App />, { 'GET /api/automap': makeAutoMap() })

    for (const hero of HEROES) {
      expect(getByRole('region', { name: hero.label })).toBeInTheDocument()
      expect(getByRole('link', { name: `${hero.label} settings` })).toHaveAttribute('href', hero.route)
    }
  })

  it('puts the egress switch on the internet page', async () => {
    at(href('internet'))
    const { getByRole } = await renderAgent(<App />)

    expect(getByRole('region', { name: 'Internet traffic' })).toBeInTheDocument()
  })

  // Inspection has more settings than the rest of Security together and a level the
  // dashboard is opened to change, so it is a section rather than a card under Security.
  it('puts traffic inspection on its own page and off the security page', async () => {
    at(href('security'))
    const security = await renderAgent(<App />)
    expect(security.getByRole('region', { name: 'Security' })).toBeInTheDocument()
    expect(security.queryByLabelText('Traffic inspection')).not.toBeInTheDocument()
    security.unmount()

    at(href('inspection'))
    const inspection = await renderAgent(<App />)
    expect(inspection.getByLabelText('Traffic inspection')).toBeInTheDocument()
  })

  // Every address a page had before it moved under Connections still opens that page,
  // and the URL bar says where it went, or the next bookmark is stale again. The rules
  // address keeps its tail: a link to one proxy's rules still opens that proxy's rules.
  it.each([
    ['the access section', '#/access', 'What can reach what', href('connections', 'grants')],
    ['the proxies page', '#/access/proxies', 'Proxies', href('connections', 'proxies')],
    [
      "one proxy's rules",
      '#/access/rules/px_default',
      'What Default may reach',
      href('connections', 'rules', 'px_default'),
    ],
    ['the mode page', '#/mode', 'Network interface', href('connections', 'paths')],
    ['the forwards page', '#/forwards', 'Port forwards', href('connections', 'forwards')],
    ['the old proxy settings', href('settings', 'proxy'), 'Proxies', href('connections', 'proxies')],
    [
      'the old interface settings',
      href('settings', 'interface'),
      'Network interface',
      href('connections', 'paths'),
    ],
    ['the old security settings', href('settings', 'security'), 'Security', href('security')],
  ])('sends %s to where it moved', async (_case, from, label, to) => {
    at(from)
    const { getByRole } = await renderAgent(<App />)

    expect(getByRole('region', { name: label })).toBeInTheDocument()
    expect(window.location.hash).toBe(to)
  })

  // Both settings moved onto the network they belong to. A link in someone's notes is how
  // people arrive at a page they use, so the old address has to land somewhere real --
  // and the URL bar has to say where, or the next bookmark is stale again.
  it.each([
    ['exitnode'],
    ['routes'],
  ])('sends the old %s address to the connections it moved to', async (section) => {
    at(href('settings', section))
    const { getByRole } = await renderAgent(<App />)

    expect(getByRole('region', { name: 'Tailscale' })).toBeInTheDocument()
    expect(window.location.hash).toBe(href('connections'))
  })

  // Both old addresses render the same page, so the page being rendered is not what says
  // whether the URL bar still names an address that moved. Watching the page instead
  // leaves the second one in the bar: it lands correctly, and the bookmark taken there is
  // stale all over again.
  it('corrects the bar again on a second address that moved', async () => {
    at(href('settings', 'routes'))
    await renderAgent(<App />)

    await goTo(href('settings', 'exitnode'))

    expect(window.location.hash).toBe(href('connections'))
  })

  // The two cards describe one network: what it routes and where its traffic leaves. Both
  // moved onto that network's page, so this is the address that has to reach them.
  it('puts the routes and exit node cards on the connection they describe', async () => {
    at('#/connections/tailscale/tn_primary')
    const { getByRole } = await renderAgent(<App />, {
      'GET /api/routes': makeRoutes({ enabled: true }),
      'GET /api/exitnode': makeExitNode({ enabled: true }),
    })

    expect(getByRole('region', { name: 'Subnet routes' })).toBeInTheDocument()
    expect(getByRole('region', { name: 'Exit node' })).toBeInTheDocument()
  })

  // Tailnet lock has no module switch: it is the tailnet's own setting. A device it holds
  // back connects, reports Running and reaches nothing, so the card has to appear without
  // anyone having enabled anything -- and stay away on a tailnet that does not use it.
  it('leaves the lock card out on a tailnet that does not use lock', async () => {
    at(href('security'))
    const { getByRole, queryByLabelText } = await renderAgent(<App />, {
      'GET /api/lock': makeLock(),
    })

    expect(getByRole('region', { name: 'Security' })).toBeInTheDocument()
    expect(queryByLabelText('Tailnet lock')).not.toBeInTheDocument()
  })

  it('shows the lock card with its remedy on a tailnet that has lock', async () => {
    at(href('security'))
    const { getByLabelText } = await renderAgent(<App />, {
      'GET /api/lock': makeLock({
        enabled: true,
        signed: false,
        signCommand: 'tailscale lock sign nodekey:abc123 tlpub:def456',
        capability: {
          available: true,
          degraded: true,
          reason: 'This device is not signed for tailnet lock yet.',
        },
      }),
    })

    expect(getByLabelText('Tailnet lock')).toHaveTextContent(
      'tailscale lock sign nodekey:abc123 tlpub:def456',
    )
  })
})

describe('the overlay a click opens', () => {
  it.each([
    ['Tag setup', 'Tag setup', 'Close'],
    ['Restart app-tail', 'Restart app-tail?', 'Close'],
  ])('opens %s and closes it again', async (button, dialogName, closeLabel) => {
    const { getByRole, queryByRole } = await renderAgent(<App />)

    expect(queryByRole('dialog')).not.toBeInTheDocument()

    fireEvent.click(getByRole('button', { name: button }))
    await settle()
    expect(getByRole('dialog')).toHaveAccessibleName(dialogName)

    fireEvent.click(getByRole('button', { name: closeLabel }))
    await settle()

    expect(queryByRole('dialog')).not.toBeInTheDocument()
  })

  it('opens an empty Add forward dialog', async () => {
    at(href('connections', 'forwards'))
    const { getByRole } = await renderAgent(<App />)

    fireEvent.click(getByRole('button', { name: 'Add forward' }))
    await settle()

    const dialog = getByRole('dialog')
    expect(dialog).toHaveAccessibleName('Add forward')
    // Scoped to the dialog: the preset table on the card behind it has a Name box of its
    // own, and an unscoped query would be as likely to read that one.
    expect(within(dialog).getByLabelText(/^Name/)).toHaveValue('')
  })

  // Edit has to carry the row's own forward through. Handing over the wrong one -- or
  // none -- silently edits a different rule than the one clicked.
  it('opens Edit prefilled from the row that was clicked', async () => {
    at(href('connections', 'forwards'))
    const { container, getByRole } = await renderAgent(<App />, {
      'GET /api/forwards': {
        forwards: [
          makeForward({ id: 'fwd-a', name: 'alpha', listenPort: 2222 }),
          makeForward({ id: 'fwd-b', name: 'bravo', listenPort: 3333 }),
        ],
      },
    })

    const bravoRow = within(container)
      .getAllByRole('row')
      .find((r) => within(r).queryByText('bravo') !== null)!
    fireEvent.click(within(bravoRow).getByRole('button', { name: 'Edit' }))
    await settle()

    const dialog = getByRole('dialog')
    expect(dialog).toHaveAccessibleName('Edit forward')
    expect(within(dialog).getByLabelText(/^Name/)).toHaveValue('bravo')
  })
})

describe('keeping the pages in step', () => {
  // A forward change can move node state and vice versa: enabling a to_tailnet rule is
  // what first brings the node up. Refreshing only the panel that was acted on leaves the
  // other showing a state that is already wrong.
  it('re-polls everything on screen after a change', async () => {
    at(href('connections', 'forwards'))
    const { container, agent } = await renderAgent(<App />, {
      'GET /api/forwards': { forwards: [makeForward({ id: 'fwd-ssh', name: 'ssh' })] },
      'POST /api/forwards/fwd-ssh/toggle': makeForward({ enabled: false }),
    })

    const statusBefore = agent.countOf('GET /api/status')
    const forwardsBefore = agent.countOf('GET /api/forwards')

    fireEvent.click(within(container).getByLabelText('Disable ssh'))
    await settle()

    expect(agent.countOf('GET /api/status')).toBe(statusBefore + 1)
    expect(agent.countOf('GET /api/forwards')).toBe(forwardsBefore + 1)
  })

  // Forgetting an assignment deletes the forwards that held it, so the table is as stale
  // as the module's own counters afterwards. Re-reading only the card that owns the button
  // leaves ports listed in the table that nothing is listening on any more.
  it('re-reads the forwards table too when assignments are forgotten', async () => {
    at(href('connections', 'forwards'))
    const { agent, getByLabelText } = await renderAgent(<App />, {
      'GET /api/automap': makeAutoMap({ enabled: true, stored: 5 }),
      'POST /api/automap/forget': {
        removed: 5,
        automap: makeAutoMap({ enabled: true, stored: 0 }),
      },
    })
    const before = agent.countOf('GET /api/forwards')

    fireEvent.click(
      within(getByLabelText('Automatic ports')).getByRole('button', {
        name: 'Forget devices that are gone',
      }),
    )
    await settle()

    expect(agent.countOf('POST /api/automap/forget')).toBe(1)
    expect(agent.countOf('GET /api/automap')).toBeGreaterThan(1)
    expect(agent.countOf('GET /api/forwards')).toBeGreaterThan(before)
  })
})

describe('a list field the agent sends as null', () => {
  // A Go nil slice marshals to null, not [], so an agent with no pref-backed setting
  // available sends "fields": null. Reading .length off that threw during render, and a
  // throw with no error boundary above it unmounts the whole tree -- the dashboard
  // appeared for one frame and then went blank. The card being absent is incidental; what
  // this pins is that the rest of the page still renders.
  it('renders the page rather than blanking it', async () => {
    at(href('security'))
    const { getByRole, queryByLabelText } = await renderAgent(<App />, {
      'GET /api/prefs': makePrefs({ fields: null }),
    })

    expect(getByRole('region', { name: 'Security' })).toBeInTheDocument()
    expect(queryByLabelText('Tailnet settings')).not.toBeInTheDocument()
  })
})

describe('the top bar', () => {
  it("shows the agent's version once it is known", async () => {
    const { getByText } = await renderAgent(<App />, {
      'GET /api/status': makeStatus({ version: '0.4.1' }),
    })

    expect(getByText('0.4.1')).toBeInTheDocument()
  })

  it('leaves the version out rather than rendering a blank badge', async () => {
    const { container } = await renderAgent(<App />, {
      'GET /api/status': makeStatus({ version: '' }),
    })

    expect(container.querySelector('.version')).not.toBeInTheDocument()
  })
})
