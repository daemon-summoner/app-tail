// SPDX-License-Identifier: MIT

import { describe, expect, it } from 'vitest'

import { failWith, makeSystemProxy, openInfo, renderAgent } from '../test/agent'
import { SystemProxySection } from './SystemProxySection'

// The agent decides in one place whether this machine is pointing at the proxy, because
// the setting lives outside the app and only the agent has looked at it. The section
// renders that answer; it must never infer it from the switch alone -- "on" and "in
// force" are different things and the gap between them is the whole point of the panel.
describe('what the section says this machine is doing', () => {
  it.each([
    [
      'a platform app-tail will not write',
      { supported: false, enabled: false },
      'pending',
      'by hand only',
    ],
    ['the switch off', { supported: true, enabled: false }, '', 'off'],
    ['the switch on and in force', { supported: true, enabled: true, applied: true }, 'running', 'pointing here'],
    ['the switch on but not in force', { supported: true, enabled: true, applied: false }, 'error', 'not applied'],
  ])('shows %s as %s', async (_case, view, tone, label) => {
    const { container } = await renderAgent(<SystemProxySection />, {
      'GET /api/proxy/system': makeSystemProxy(view),
    })

    const status = container.querySelector('.proxy-system-head .status')
    expect(status).toHaveTextContent(label)
    // The whole class list, not just the expected tone: a state that also carried a
    // second tone would render two colours and still pass a toHaveClass check.
    expect(status?.className.trim()).toBe(tone === '' ? 'status' : `status ${tone}`)
  })
})

// A switch that silently reaches less than it claims is the failure this whole module
// risks, so the limits stay reachable wherever it is offered -- including when it is
// working, which is exactly when someone is deciding whether to trust it.
describe('what the setting does not reach', () => {
  const LIMITS = ['Firefox has its own setting.', 'Applies to this Windows user only.']

  const applied = () => ({
    'GET /api/proxy/system': makeSystemProxy({
      supported: true,
      enabled: true,
      applied: true,
      autoConfigUrl: 'http://127.0.0.1:8377/proxy.pac',
      managed: true,
      capability: { available: true, degraded: false, limits: LIMITS },
    }),
  })

  it('states them even when the setting is applied', async () => {
    const { container } = await renderAgent(<SystemProxySection />, applied())

    const info = openInfo(container, "this machine's proxy settings")
    for (const limit of LIMITS) expect(info).toHaveTextContent(limit)
  })

  // One press away rather than a permanent list under the switch. Reaching them is the
  // promise; a limit found without opening anything has leaked back onto the section.
  it('keeps them out of the section until they are asked for', async () => {
    const { queryByText } = await renderAgent(<SystemProxySection />, applied())

    for (const limit of LIMITS) expect(queryByText(limit)).not.toBeInTheDocument()
  })
})

// Someone else's proxy URL is not a failure and must not read as one: it is the value
// app-tail records before replacing, and the reason a corporate PAC survives the round
// trip. Reporting it as an error would push a user into "fixing" it.
it('reports a value something else set without calling it a problem', async () => {
  const { container, getByText } = await renderAgent(<SystemProxySection />, {
    'GET /api/proxy/system': makeSystemProxy({
      supported: true,
      enabled: false,
      autoConfigUrl: 'http://proxy.corp.example.com/company.pac',
      managed: false,
      capability: { available: true, degraded: false },
    }),
  })

  expect(getByText(/proxy\.corp\.example\.com\/company\.pac/)).toBeInTheDocument()
  expect(container.querySelector('.notice.error')).toBeNull()
})

// The commands are the only thing a macOS user can act on, so they have to be present
// and they have to name the running proxy. A section that showed the refusal without
// them would be a dead end.
it('offers the commands the agent rendered, with the proxy in them', async () => {
  const { getByText } = await renderAgent(<SystemProxySection />, {
    'GET /api/proxy/system': makeSystemProxy({
      manual: [
        {
          label: 'Point this Mac at it (needs an administrator, and covers one network service)',
          command:
            'networksetup -listallnetworkservices\nsudo networksetup -setautoproxyurl "Wi-Fi" http://127.0.0.1:8377/proxy.pac',
        },
      ],
    }),
  })

  expect(
    getByText('Point this Mac at it (needs an administrator, and covers one network service)'),
  ).toBeInTheDocument()
  expect(getByText(/setautoproxyurl "Wi-Fi" http:\/\/127\.0\.0\.1:8377\/proxy\.pac/)).toBeInTheDocument()
})

// This section reads a value outside the app; the proxy above it does not. A failure
// here says nothing about whether the proxy is working, so it must not take over the
// panel it sits in.
it('keeps its own failure inside itself', async () => {
  const { container, getByText } = await renderAgent(<SystemProxySection />, {
    'GET /api/proxy/system': failWith(500, 'the registry could not be read'),
  })

  expect(getByText('the registry could not be read')).toBeInTheDocument()
  expect(container.querySelector('.proxy-system-head')).toBeNull()
})
