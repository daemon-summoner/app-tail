// SPDX-License-Identifier: MIT

// The three ways this machine reaches its networks, each with what it is doing and the
// switch that turns it on, decided from the views the agent serves and nothing else.
//
// This is the whole decision and none of the drawing: every branch in here is reachable
// from a test with plain values, and the tiles that show the result carry no branch of
// their own. The forwards always run; the proxy and the interface are module switches,
// and the interface's switch also has to name a mode, because the module switch on its
// own puts the node on no interface at all.

import type {
  AutoMapView,
  FabricView,
  Forward,
  InterfaceView,
  ProxyView,
  RestartClass,
  SettingFieldSchema,
} from '../../api'
import { MODES, type ModeStatus } from './modes'

const TUN_VALUE = 'tun'
const FABRIC_VALUE = 'fabric'
const INTERFACE_MODE_KEY = 'interface.mode'

/** forwardsStatus counts what the forwards are actually doing. An enabled forward that
 *  is not running is the failure worth a colour, which is the same rule the tray's line
 *  and the icon's dot follow. */
export function forwardsStatus(
  forwards: readonly Forward[],
  automap: AutoMapView | undefined,
): ModeStatus {
  const enabled = forwards.filter((f) => f.enabled)
  const running = enabled.filter((f) => f.state === 'running')
  const mapped = automap?.enabled ? `, ${automap.mapped} automatic` : ''
  if (forwards.length === 0) return { tone: 'off', label: 'none yet' }
  if (enabled.length === 0) return { tone: 'off', label: `${forwards.length} configured, all off` }
  if (running.length < enabled.length) {
    return { tone: 'error', label: `${running.length} of ${enabled.length} running${mapped}` }
  }
  return { tone: 'running', label: `${running.length} running${mapped}` }
}

/** proxyStatus reads the answer the agent already gave in `capability`, so the tiles and
 *  the card they point at cannot disagree about whether the proxy is working. */
export function proxyStatus(proxy: ProxyView | undefined): ModeStatus {
  if (!proxy?.enabled) return { tone: 'off', label: 'off' }
  if (!proxy.capability.available) return { tone: 'error', label: 'not listening' }
  if (proxy.capability.degraded) return { tone: 'pending', label: 'degraded' }
  return { tone: 'running', label: proxy.listening ?? 'listening' }
}

/** interfaceStatus leads with whether the node is really on an interface, which is not
 *  the same as the mode being switched on: a node that could not create one falls back
 *  and keeps running, and only this tells the two apart. */
export function interfaceStatus(
  tun: InterfaceView | undefined,
  fabric: FabricView | undefined,
): ModeStatus {
  // No view yet is not the module being off: the agent has not answered, or could not.
  if (!tun) return { tone: 'pending', label: 'reading' }
  if (tun.inForce) {
    return { tone: 'running', label: tun.interface ? `on ${tun.interface}` : 'in force' }
  }
  if (!tun.enabled) return { tone: 'off', label: 'off' }
  if (tun.fallback) return { tone: 'error', label: 'fell back' }
  // The other mode that puts this machine on an interface. The view above is the tailnet's
  // own, and it reports "not selected" for a machine whose every connection is on one
  // interface -- which is the arrangement reading as no arrangement at all.
  if (tun.configured === FABRIC_VALUE) return fabricStatus(fabric)
  if (tun.configured === TUN_VALUE) return { tone: 'pending', label: 'waiting for a restart' }
  return { tone: 'off', label: 'not selected' }
}

/** fabricStatus is the one-interface-for-every-network mode, which is in force only while
 *  something is really carrying those networks: an interface that is up and carrying
 *  nothing leaves every address on every connection unreachable. */
export function fabricStatus(fabric: FabricView | undefined): ModeStatus {
  if (fabric?.running) {
    return { tone: 'running', label: fabric.interface ? `on ${fabric.interface}` : 'carrying' }
  }
  if (fabric?.error) return { tone: 'error', label: 'not carrying' }
  return { tone: 'pending', label: 'waiting for a restart' }
}

/** PathControl is the switch beside a path, or the fact that it has none. `reading` is a
 *  switch whose on-patch depends on a view the agent has not served yet, so there is no
 *  patch to offer. `restart` is the class of restart the switch's patch owes, so the
 *  control can say so before the click rather than in a notice after it. */
export type PathControl =
  | { kind: 'always' }
  | { kind: 'reading' }
  | {
      kind: 'switch'
      on: boolean
      patchOn: Record<string, unknown>
      patchOff: Record<string, unknown>
      restart: RestartClass | undefined
    }

export interface AccessPath {
  id: string
  label: string
  route: string
  status: ModeStatus
  control: PathControl
}

/** AccessPathViews are the served views each path's state is read from. */
export interface AccessPathViews {
  forwards: readonly Forward[]
  automap: AutoMapView | undefined
  proxy: ProxyView | undefined
  tun: InterfaceView | undefined
  /** What the one interface for every connection is carrying, for the machines arranged
   *  that way: the tailnet's own view has nothing to say about them. */
  fabric: FabricView | undefined
}

/** AccessPathDraft is what the settings form holds for the two switches: the stored
 *  value, which is what a switch shows, as opposed to what is in force, which the status
 *  beside it shows. */
export interface AccessPathDraft {
  proxyEnabled: boolean
  interfaceEnabled: boolean
}

/**
 * accessPaths decides every path's state and control at once, in the tiles' order.
 *
 * Switching the interface on writes the mode with it: `tun` unless the machine is already
 * arranged for the one-interface mode, in which case that arrangement is kept. Switching
 * it off writes only the module switch, so the mode is remembered for the next time: the
 * served view's `configured` is what the switch turns on, and while the module is off
 * that is the remembered mode, not the stored one. Until that view has arrived the switch
 * has no mode to write, so it offers none: a click before then would write `tun` over an
 * arrangement it never saw.
 */
export function accessPaths(
  draft: AccessPathDraft,
  views: AccessPathViews,
  fields: readonly SettingFieldSchema[],
): AccessPath[] {
  const interfaceMode = fields.find((f) => f.key === INTERFACE_MODE_KEY)
  const interfaceControl = (tun: InterfaceView): PathControl => ({
    kind: 'switch',
    on: draft.interfaceEnabled,
    patchOn: {
      'interface.enabled': true,
      'interface.mode': tun.configured === FABRIC_VALUE ? FABRIC_VALUE : TUN_VALUE,
    },
    patchOff: { 'interface.enabled': false },
    restart: interfaceMode?.restart,
  })
  return MODES.map((mode) => {
    switch (mode.id) {
      case 'proxy':
        return {
          ...mode,
          status: proxyStatus(views.proxy),
          control: {
            kind: 'switch',
            on: draft.proxyEnabled,
            patchOn: { 'proxy.enabled': true },
            patchOff: { 'proxy.enabled': false },
            restart: undefined,
          },
        }
      case 'interface':
        return {
          ...mode,
          status: interfaceStatus(views.tun, views.fabric),
          control: views.tun === undefined ? { kind: 'reading' } : interfaceControl(views.tun),
        }
      default:
        return {
          ...mode,
          status: forwardsStatus(views.forwards, views.automap),
          control: { kind: 'always' },
        }
    }
  })
}
