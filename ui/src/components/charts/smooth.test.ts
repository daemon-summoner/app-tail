// SPDX-License-Identifier: MIT

import { describe, expect, it } from 'vitest'

import { smooth } from './smooth'

/** WINDOW is how many seconds one reading is spread across: its own and the 24 after it. */
const WINDOW = 25

/** quiet is n seconds of nothing moving. */
const quiet = (n: number): number[] => Array<number>(n).fill(0)

describe('averaging a series for drawing', () => {
  // A plain running mean draws a one-second burst as a flat-topped block with square
  // shoulders, which is the jagged look the averaging is there to remove. The line should
  // rise to one peak and fall away from it, the way a market chart's moving average does.
  it('draws a burst as one rounded hump rather than a flat-topped block', () => {
    const drawn = smooth([...quiet(40), 900, ...quiet(40)]) as number[]
    const hump = drawn.slice(40, 40 + WINDOW)

    const top = Math.max(...hump)
    expect(hump.filter((v) => v === top)).toHaveLength(1)
    const crest = hump.indexOf(top)
    for (let i = 1; i <= crest; i++) expect(hump[i]!).toBeGreaterThan(hump[i - 1]!)
    for (let i = crest + 1; i < hump.length; i++) expect(hump[i]!).toBeLessThan(hump[i - 1]!)
  })

  // Second-to-second jitter is what made the line unreadable. Once the averaging has a full
  // run behind it, a repeating pattern of bursts and pauses has to draw as a nearly level
  // line at its mean rather than as a row of teeth.
  it('flattens second-to-second jitter into a nearly level line', () => {
    const pattern = [0, 400, 0, 0, 250, 0, 100, 0, 0, 300, 50]
    const jitter = Array.from({ length: 150 }, (_, i) => pattern[i % pattern.length]!)
    const settled = (smooth(jitter) as number[]).slice(WINDOW)

    expect(Math.max(...settled) - Math.min(...settled)).toBeLessThan(400 / 100)
  })

  // Averaging moves traffic later in time; it must not add or lose any. A drawn line whose
  // area differs from what was measured would overstate or understate the transfer.
  it('carries exactly the traffic that was measured, spread over the seconds after it', () => {
    const drawn = smooth([...quiet(40), 900, ...quiet(40)]) as number[]

    expect(drawn.reduce((sum, v) => sum + v, 0)).toBeCloseTo(900, 9)
  })

  // Without this the average would keep counting readings that have left the window, and a
  // burst would be carried for the rest of the series.
  it('lets a burst leave the line entirely once the window has passed it', () => {
    const drawn = smooth([...quiet(40), 900, ...quiet(40)])

    expect(drawn[40 + WINDOW - 1]).toBeGreaterThan(0)
    expect(drawn[40 + WINDOW]).toBe(0)
  })

  // The first seconds of a run have fewer readings behind them than the window holds.
  // Dividing those by the full window would draw a transfer already running when the
  // window opened as ramping up from nothing.
  it('draws a steady rate at that rate from the very first reading', () => {
    for (const value of smooth(Array<number>(40).fill(1000))) {
      expect(value).toBeCloseTo(1000, 9)
    }
  })

  // "Nothing moved" and "nobody looked" are different statements, and averaging across the
  // gap would draw a rate from before a stretch of time the agent cannot account for.
  it('starts again after an unmeasured interval, which stays a gap', () => {
    expect(smooth([100, 100, null, 50])).toEqual([100, 100, null, 50])
  })

  // The average only ever looks backwards. A centred one would draw part of a burst into
  // the seconds before it, which is traffic at a time the agent measured none.
  it('leaves the readings before a burst where they were measured', () => {
    const drawn = smooth([0, 0, 900])

    expect(drawn.slice(0, 2)).toEqual([0, 0])
    expect(drawn[2]).toBeGreaterThan(0)
  })
})
