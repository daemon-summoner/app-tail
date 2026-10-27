// SPDX-License-Identifier: MIT

import { describe, expect, it } from 'vitest'

import { makeTrafficSeries } from '../../test/agent'
import { hasReadings, linesFor, matches, optionsFor, OTHER_KEY, total, visible } from './breakdown'

describe('filtering a breakdown', () => {
  const rows = [
    makeTrafficSeries({ key: 'a', label: 'tcp/445', via: 'wg1', peer: 'n1' }),
    makeTrafficSeries({ key: 'b', label: 'tcp/443', via: 'tn_primary' }),
    makeTrafficSeries({ key: OTHER_KEY, label: 'Everything else' }),
  ]

  it('keeps only what the chosen connection carried', () => {
    const kept = rows.filter((s) => matches(s, { via: 'wg1' })).map((s) => s.key)

    expect(kept).toContain('a')
    expect(kept).not.toContain('b')
  })

  it('keeps only what the chosen device reached', () => {
    const kept = rows.filter((s) => matches(s, { peer: 'n1' })).map((s) => s.key)

    expect(kept).toEqual(['a', OTHER_KEY])
  })

  // The folded line is where the traffic a filter would otherwise lose could be: it stands
  // for keys the cap never named, so nothing here knows it does not belong to the filter.
  // Dropping it makes a filtered chart claim a completeness it does not have.
  it('never filters away the line standing for everything else', () => {
    expect(matches(rows[2]!, { via: 'wg1', peer: 'n9' })).toBe(true)
  })

  it('leaves a breakdown alone when nothing is chosen', () => {
    expect(visible({ lane: 'ports', intervalSec: 1, windowSec: 300, series: rows }, {})).toEqual(
      rows,
    )
  })
})

describe('the lines a breakdown draws', () => {
  const rows = [
    makeTrafficSeries({ key: 'a', label: 'nas', up: [10, 20], down: [1, 2] }),
    makeTrafficSeries({ key: 'b', label: 'laptop', up: [5, 5], down: [0, 0] }),
    makeTrafficSeries({ key: OTHER_KEY, label: 'Everything else', up: [1, 1], down: [1, 1] }),
  ]

  // One key has to be one line on both charts, or an upload cannot be read against the
  // download that answered it.
  it('gives a key the same mark in both directions', () => {
    const up = linesFor(rows, 'up', false)
    const down = linesFor(rows, 'down', false)

    expect(up.map((l) => l.tone)).toEqual([0, 1, undefined])
    expect(down.map((l) => l.tone)).toEqual(up.map((l) => l.tone))
  })

  // The palette defines eight marks. A ninth line wearing one of them would be a second
  // series with the first one's colour and dash pattern, which is exactly the confusion the
  // marks exist to prevent.
  it('draws the folded line muted rather than as a ninth colour', () => {
    const folded = linesFor(rows, 'up', false)[2]!

    expect(folded.muted).toBe(true)
    expect(folded.tone).toBeUndefined()
  })

  it('draws each direction from its own readings', () => {
    expect(linesFor(rows, 'up', false)[0]!.values).toEqual([10, 20])
    expect(linesFor(rows, 'down', false)[0]!.values).toEqual([1, 2])
  })

  it('smooths only when asked', () => {
    expect(linesFor(rows, 'up', true)[0]!.values).toEqual([10, 11.25])
    expect(linesFor(rows, 'up', false)[0]!.values).toEqual([10, 20])
  })

  // A window whose every column is a null is a lane nothing has been measured for, and a
  // chart of nothing reads as a quiet network rather than as an absence of measurement.
  it('says a lane holds nothing worth drawing when every reading is missing', () => {
    expect(hasReadings([makeTrafficSeries({ up: [null, null], down: [null, null] })])).toBe(false)
    expect(hasReadings([makeTrafficSeries({ up: [1, 2], down: [null, null] })])).toBe(true)
    // One measured column is a dot, not a line: a rate needs two.
    expect(hasReadings([makeTrafficSeries({ up: [null, 2], down: [null, null] })])).toBe(false)
  })

  it('adds up the most recent reading of every line', () => {
    // The latest measured column of each, not the last column outright: a key that missed
    // the most recent tick still carried what it last reported.
    const gapped = [
      makeTrafficSeries({ key: 'a', up: [10, 20] }),
      makeTrafficSeries({ key: 'b', up: [5, null] }),
    ]

    expect(total(gapped, 'up')).toBe(25)
  })
})

describe('the filter choices a lane offers', () => {
  const rows = [
    makeTrafficSeries({ key: 'a', via: 'wg1', peer: 'n1' }),
    makeTrafficSeries({ key: 'b', via: 'wg1' }),
    makeTrafficSeries({ key: 'c', via: 'tn_primary', peer: 'n2' }),
    makeTrafficSeries({ key: OTHER_KEY }),
  ]
  const labels = new Map([
    ['wg1', 'work'],
    ['tn_primary', 'tailnet'],
    ['n1', 'nas'],
  ])

  it('offers each connection once, under the name it goes by', () => {
    expect(optionsFor(rows, 'via', labels)).toEqual([
      { id: 'tn_primary', label: 'tailnet' },
      { id: 'wg1', label: 'work' },
    ])
  })

  // A device the peer list has forgotten still appears in rows the window already holds.
  // Leaving it out would make its traffic unreachable through the filter that names it.
  it('falls back on the id for something it has no name for', () => {
    expect(optionsFor(rows, 'peer', labels)).toEqual([
      { id: 'n2', label: 'n2' },
      { id: 'n1', label: 'nas' },
    ])
  })

  it('offers nothing for a field no row names', () => {
    expect(optionsFor([makeTrafficSeries({ key: 'a' })], 'via', labels)).toEqual([])
  })
})
