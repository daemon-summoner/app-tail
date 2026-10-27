// SPDX-License-Identifier: MIT

// The inspection ladder: four rungs read out of, and written back as, the switches the
// engine already has.
//
// There is no level setting in the agent, and this file does not pretend there is. A rung
// is a name for one combination of the engine's switches, and the rung a machine is on is
// those switches read back -- so choosing a rung and seeing which is chosen cannot
// disagree, and a machine set to a combination that is nobody's rung says so rather than
// rounding to the nearest one.

import type { IPSView } from '../api'

export type InspectionLevel = 'off' | 'basic' | 'deep' | 'full' | 'custom'

/** The rungs somebody can choose, lowest first. `custom` is read, never chosen. */
export const INSPECTION_RUNGS = ['off', 'basic', 'deep', 'full'] as const

export type InspectionRung = (typeof INSPECTION_RUNGS)[number]

/** The switches a rung is read from. The served view is the input rather than the
 *  settings draft, because the draft drops every `ips.*` field while the module is off.
 *  The user's own byte patterns are on no rung: they match against a list only the user
 *  writes, so a rung that switched them on would leave a machine with none written
 *  looking for nothing. The ladder neither reads nor writes `ips.payload`. */
export type InspectionSwitches = Pick<
  IPSView,
  'enabled' | 'names' | 'destinations' | 'handshake' | 'fingerprints' | 'anomaly'
> & { intercept: Pick<IPSView['intercept'], 'mode'> }

/** What each rung is called and what it adds, for the control that offers them. */
export const INSPECTION_RUNG_TEXT: Record<InspectionRung, { name: string; summary: string }> = {
  off: { name: 'Off', summary: 'Nothing is looked at.' },
  basic: {
    name: 'Basic',
    summary: 'Names and addresses: each connection is checked against the lists.',
  },
  deep: {
    name: 'Deep',
    summary: 'Also the opening bytes of every connection, and the pattern of them together.',
  },
  full: {
    name: 'Full',
    summary: 'Also opens encrypted connections, which needs a root certificate on this machine.',
  },
}

const INTERCEPT_OFF = 'off'
/** The interception mode a rung switches on: everything except the destinations named,
 *  which is the mode the shipped exception list is written for. */
const INTERCEPT_EXCEPT = 'except'

const BASIC = {
  'ips.enabled': true,
  'ips.names': true,
  'ips.destinations': true,
  'ips.handshake': false,
  'ips.fingerprints': false,
  'ips.anomaly': false,
  'ips.intercept': INTERCEPT_OFF,
} as const

const DEEP = {
  ...BASIC,
  'ips.handshake': true,
  'ips.fingerprints': true,
  'ips.anomaly': true,
} as const

/**
 * rungPatch is what choosing a rung writes. Every rung above Off carries every switch a
 * rung is read from: a rung is a position, not a delta, so choosing Basic from Deep
 * switches the deep signals off rather than leaving whatever was there. Off writes the
 * module switch alone, which is what shelves the rest. Full carries no agreement: that is
 * said by the person, through the dialog that asks, and never by a rung.
 */
export function rungPatch(rung: InspectionRung): Record<string, unknown> {
  switch (rung) {
    case 'off':
      return { 'ips.enabled': false }
    case 'basic':
      return { ...BASIC }
    case 'deep':
      return { ...DEEP }
    case 'full':
      return { ...DEEP, 'ips.intercept': INTERCEPT_EXCEPT }
  }
}

/** inspectionLevel reads which rung a machine is on, or `custom` for a combination that
 *  is none of them. Off is off whatever the other switches say: they are not read while
 *  the module is off, and a ladder that showed Deep on a machine inspecting nothing would
 *  be wrong in the one way that matters. Full is the interception mode Full writes and no
 *  other: a machine opening only the destinations it names is on no rung, because a rung
 *  shown as chosen is a rung a click re-writes, and that click would widen the opening
 *  to everything else. */
export function inspectionLevel(view: InspectionSwitches): InspectionLevel {
  if (!view.enabled) return 'off'
  const basic = view.names && view.destinations
  const deep = view.handshake && view.fingerprints && view.anomaly
  const shallow = !view.handshake && !view.fingerprints && !view.anomaly
  const mode = view.intercept.mode
  if (!basic) return 'custom'
  if (deep && mode === INTERCEPT_EXCEPT) return 'full'
  if (deep && mode === INTERCEPT_OFF) return 'deep'
  if (shallow && mode === INTERCEPT_OFF) return 'basic'
  return 'custom'
}
