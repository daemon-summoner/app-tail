// SPDX-License-Identifier: MIT

import { describe, expect, it } from 'vitest'

import {
  INSPECTION_RUNGS,
  inspectionLevel,
  rungPatch,
  type InspectionSwitches,
} from './inspectionLevel'

/** switches builds the served view the ladder reads, from a fresh install's answer. */
function switches(over: Partial<InspectionSwitches> = {}): InspectionSwitches {
  return {
    enabled: false,
    names: false,
    destinations: false,
    handshake: false,
    fingerprints: false,
    anomaly: false,
    intercept: { mode: 'off' },
    ...over,
  }
}

/** served is what the agent would report after storing a rung's patch: each `ips.x` key
 *  lands on the view's `x`, and the interception mode on its own field. */
function served(patch: Record<string, unknown>, from: InspectionSwitches = switches()): InspectionSwitches {
  const next = { ...from, intercept: { ...from.intercept } }
  for (const [key, value] of Object.entries(patch)) {
    const field = key.slice('ips.'.length)
    if (field === 'intercept') next.intercept.mode = String(value)
    else (next as unknown as Record<string, unknown>)[field] = value
  }
  return next
}

describe('reading the rung a machine is on', () => {
  // The contract the whole control rests on: what choosing a rung writes is what the
  // ladder reads back as that rung, from any starting point.
  it.each(INSPECTION_RUNGS)('reads %s back after choosing it', (rung) => {
    for (const start of INSPECTION_RUNGS) {
      const before = served(rungPatch(start), switches({ enabled: true }))
      expect(inspectionLevel(served(rungPatch(rung), before))).toBe(rung)
    }
  })

  // Off is decided by the module switch alone. The other switches are not read while it
  // is off, and a ladder showing Deep over a machine inspecting nothing would be wrong in
  // the one way that matters.
  it('reads a machine with every switch on and the module off as off', () => {
    const view = served(rungPatch('full'))
    expect(inspectionLevel({ ...view, enabled: false })).toBe('off')
  })

  it.each([
    ['the deep signals without the names', { names: false, handshake: true, fingerprints: true, anomaly: true }],
    ['fingerprints without the handshake they need', { handshake: false, fingerprints: true }],
    ['one deep signal on its own', { anomaly: true }],
    ['interception over the basic signals alone', { intercept: { mode: 'only' } }],
  ])('reads %s as a combination that is nobody’s rung', (_case, over) => {
    const basic = served(rungPatch('basic'))
    expect(inspectionLevel({ ...basic, ...over })).toBe('custom')
  })

  it('reads the deep signals with interception off as deep, not full', () => {
    const full = served(rungPatch('full'))
    expect(inspectionLevel({ ...full, intercept: { mode: 'off' } })).toBe('deep')
  })

  // Full is shown as chosen only where a click on Full would change nothing. A machine
  // opening only the destinations it names is not there: Full writes the other mode, and
  // a ladder that showed it as Full would have one click widen the opening to everything
  // else without a word said first.
  it('reads opening only the named destinations as nobody’s rung, not as full', () => {
    const deep = served(rungPatch('deep'))
    expect(inspectionLevel({ ...deep, intercept: { mode: 'only' } })).toBe('custom')
    expect(inspectionLevel({ ...deep, intercept: { mode: 'except' } })).toBe('full')
  })
})

describe('what choosing a rung writes', () => {
  // A rung is a position, not a delta: choosing Basic from Deep has to switch the deep
  // signals off, so every rung above off names every switch a rung is read from.
  it('names every switch on every rung above off', () => {
    const keys = Object.keys(rungPatch('basic')).sort()
    expect(keys).toEqual(
      [
        'ips.anomaly',
        'ips.destinations',
        'ips.enabled',
        'ips.fingerprints',
        'ips.handshake',
        'ips.intercept',
        'ips.names',
      ].sort(),
    )
    expect(Object.keys(rungPatch('deep')).sort()).toEqual(keys)
    expect(Object.keys(rungPatch('full')).sort()).toEqual(keys)
  })

  // The user's own byte patterns match against a list only they write. A rung that
  // switched them on would leave a machine with none written reported as looking for
  // nothing, so no rung touches them, and whether they are on never moves the ladder.
  it('leaves the user’s own byte patterns alone', () => {
    for (const rung of INSPECTION_RUNGS) {
      expect(rungPatch(rung)).not.toHaveProperty('ips.payload')
    }
    const deep = { ...served(rungPatch('deep')), payload: true } as InspectionSwitches & { payload: boolean }
    expect(inspectionLevel(deep)).toBe('deep')
  })

  it('switches only the module off for off, leaving the rest as they were', () => {
    expect(rungPatch('off')).toEqual({ 'ips.enabled': false })
  })

  // The agreement is the person's to give, through the dialog that says what it means.
  // A rung that wrote it would agree on their behalf.
  it('never writes the agreement', () => {
    for (const rung of INSPECTION_RUNGS) {
      expect(rungPatch(rung)).not.toHaveProperty('ips.interceptAgreed')
    }
  })

  it('opens connections only on full', () => {
    expect(rungPatch('basic')['ips.intercept']).toBe('off')
    expect(rungPatch('deep')['ips.intercept']).toBe('off')
    expect(rungPatch('full')['ips.intercept']).toBe('except')
  })
})
