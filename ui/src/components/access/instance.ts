// SPDX-License-Identifier: MIT

// What one proxy instance is, read off the view the agent serves.
//
// Every one of these is a reading rather than a decision: whether an instance is listening,
// which addresses it published and which connections a rule may name are all the agent's
// answers. They live here so the grants list, the instance cards and the rules table read
// them the same way.

import { THIS_MACHINE, type ProxyInstanceView, type TunnelView } from '../../api'
import { href } from '../../lib/router'

/** The state an instance is in, as one word plus the colour class that goes with it.
 *  Off is a state rather than a fault, which is the whole reason this is not just
 *  `capability.available`. */
export function instanceState(view: ProxyInstanceView): { tone: string; label: string } {
  if (!view.enabled) return { tone: 'off', label: 'off' }
  if (!view.capability.available) return { tone: 'error', label: 'not listening' }
  if (view.capability.degraded) return { tone: 'pending', label: 'degraded' }
  return { tone: 'running', label: 'listening' }
}

/** One address a program is pointed at, with what it is for. Each is omitted from the
 *  response rather than sent empty, so one the agent left out is skipped instead of drawn
 *  as a blank line with a copy button that copies nothing. */
export interface InstanceAddress {
  label: string
  value: string
  hint: string
}

export function addressesOf(view: ProxyInstanceView): InstanceAddress[] {
  const all = [
    {
      label: 'SOCKS5',
      value: view.socksUrl,
      hint: 'socks5h leaves the name for the proxy to resolve, which is what makes private names work',
    },
    {
      label: 'HTTP',
      value: view.httpUrl,
      hint: 'for HTTP_PROXY and tools that mishandle a socks scheme there',
    },
    {
      label: 'Local socket',
      value: view.localSocket,
      hint: 'the kernel vouches for the account at the other end of this one, which no port can do',
    },
    {
      label: 'Auto-config',
      value: view.pacUrl,
      hint: 'point a browser here: private names go through the proxy, everything else goes direct',
    },
  ]
  return all.flatMap((a) => (a.value ? [{ ...a, value: a.value }] : []))
}

/** The address of one instance's rules, which is where every "change what this reaches"
 *  link goes. */
export function rulesHref(view: ProxyInstanceView): string {
  return href('connections', 'rules', view.id)
}

/** One choice in a rule's connection picker: what it writes, and what it is called.
 *
 *  The two that are not connections come first because they are the two most rules name:
 *  any connection at all, and this machine's own network -- which an instance cannot reach
 *  unless a rule says so.
 */
export interface TunnelChoice {
  value: string
  label: string
}

export function tunnelChoices(tunnels: readonly TunnelView[]): TunnelChoice[] {
  return [
    { value: '', label: 'Any connection' },
    { value: THIS_MACHINE, label: "This machine's own network" },
    ...tunnels.map((t) => ({ value: t.id, label: t.name })),
  ]
}
