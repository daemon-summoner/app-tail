// SPDX-License-Identifier: MIT

import { describe, expect, it } from 'vitest'

import { elapsedTicks, formatElapsed, niceMax, valueTicks } from './scale'

describe('rounding a peak up to a readable maximum', () => {
  // The point of rounding up is that the axis gets a number a reader recognises and the
  // peak sits visibly below the top edge -- which is also how a peak is told from a
  // reading that was clipped off the top of the chart.
  it('leaves the peak below the top of the scale', () => {
    expect(niceMax(30)).toBe(50)
    expect(niceMax(1.4)).toBe(2)
  })

  it('rounds to the same steps at every magnitude', () => {
    expect(niceMax(120_000)).toBe(200_000)
    expect(niceMax(0.012)).toBe(0.02)
  })

  it('keeps a peak that is already a round step', () => {
    expect(niceMax(50)).toBe(50)
  })

  // log10 of zero is -Infinity and every coordinate derived from it is NaN, which renders
  // as a blank chart with no error anywhere to explain it.
  it('answers a usable scale for a machine that carried nothing', () => {
    expect(niceMax(0)).toBe(1)
    expect(niceMax(Number.NaN)).toBe(1)
  })
})

describe('the labels down the side of a chart', () => {
  it('divides the scale evenly and labels each step the way the chart writes its figures', () => {
    const ticks = valueTicks(100, (value) => `${value.toFixed(0)} B/s`)
    expect(ticks.map((tick) => tick.label)).toEqual(['33 B/s', '67 B/s', '100 B/s'])
    expect(ticks.map((tick) => tick.fraction)).toEqual([1 / 3, 2 / 3, 1])
  })

  // Zero is the plot's own baseline. Labelling it spends a row of text saying the chart
  // starts at nothing, which every chart in this kit does.
  it('leaves the zero line unlabelled', () => {
    expect(valueTicks(100, String).some((tick) => tick.value === 0)).toBe(false)
  })

  // An idle machine has a scale of a byte a second, whose lower thirds both write as
  // "0 B/s". Drawing them puts the word for nothing a third of the way up the plot, above
  // the baseline that is where nothing actually is.
  it('never labels a line with the figure it writes for nothing', () => {
    const ticks = valueTicks(1, (value) => `${Math.round(value)} B/s`)
    expect(ticks.map((tick) => tick.label)).toEqual(['1 B/s'])
    expect(ticks[ticks.length - 1]?.fraction).toBe(1)
  })

  // Two connections over three steps rounds the lower two to the same whole number. Both
  // are real heights, so neither is the zero case above -- the axis still only needs one.
  it('drops a step whose figure repeats the one below it, keeping the top of the scale', () => {
    const ticks = valueTicks(2, (value) => `${Math.round(value)}`)
    expect(ticks.map((tick) => tick.label)).toEqual(['1', '2'])
    expect(ticks[ticks.length - 1]?.fraction).toBe(1)
  })

  it('draws no scale at all when there is no scale to draw', () => {
    expect(valueTicks(0, String)).toEqual([])
    expect(valueTicks(100, String, 0)).toEqual([])
  })
})

describe('the labels along the bottom of a chart', () => {
  // The window is minutes long and sits beside a figure for right now, so "how long ago"
  // is the question a reader is actually asking of it.
  it('says how far back each place on the axis reaches, ending at now', () => {
    expect(elapsedTicks(61, 1).map((tick) => tick.label)).toEqual([
      '1m ago',
      '45s ago',
      '30s ago',
      '15s ago',
      'now',
    ])
  })

  // The cadence is the agent's, not this component's. A chart drawn at the wrong interval
  // labels a five-minute window as one minute and looks entirely correct doing it.
  it('is built from the interval it was measured at, not from the number of columns', () => {
    expect(elapsedTicks(61, 10)[0]?.label).toBe('10m ago')
  })

  // Labels are whole units, so both ends of a 90-second window read "1m ago" while the
  // axis is genuinely 90 seconds wide. One of them is a line saying nothing.
  it('labels a place once, however coarse the unit it is written in', () => {
    const labels = elapsedTicks(87, 1).map((tick) => tick.label)
    expect(labels).toEqual([...new Set(labels)])
    expect(labels[0]).toBe('1m ago')
    expect(labels[labels.length - 1]).toBe('now')
  })

  // Every label of a two-second window rounds to the same second, so asking for four of
  // them puts "1s ago" on the axis three times over and says nothing.
  it('labels a short window fewer times rather than repeating the same second', () => {
    const ticks = elapsedTicks(2, 1)
    expect(ticks.map((tick) => tick.label)).toEqual(['1s ago', 'now'])
  })

  it('draws no axis for a window that cannot span anything', () => {
    expect(elapsedTicks(1, 1)).toEqual([])
    expect(elapsedTicks(61, 0)).toEqual([])
  })
})

describe('writing a duration for an axis', () => {
  it('uses one whole unit, so a label fits under a column', () => {
    expect(formatElapsed(30)).toBe('30s')
    expect(formatElapsed(90)).toBe('2m')
    expect(formatElapsed(7200)).toBe('2h')
    expect(formatElapsed(172_800)).toBe('2d')
  })
})
