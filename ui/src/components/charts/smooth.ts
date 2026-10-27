// SPDX-License-Identifier: MIT

import type { Reading } from './geometry'

/** SPAN is how many samples one pass of the running mean covers. Odd, so a burst is drawn
 *  with a single crest rather than two equal ones side by side. */
const SPAN = 9

/** PASSES is how many times the running mean is applied. One pass draws a burst as a
 *  flat-topped block with square shoulders; each further pass rounds it, and three is
 *  close enough to a bell curve that the line reads like a market chart's moving average. */
const PASSES = 3

/**
 * smooth draws each value as a weighted mean of its own reading and the ones measured
 * before it, about the last 25 seconds, weighted most heavily toward the middle of that
 * stretch.
 *
 * A once-a-second rate is spiky enough that the shape of a transfer is hard to see through
 * the sampling noise. Every value drawn is still a mean of real readings, the total the line
 * carries is the total measured, and the card's headline stays the raw latest sample, so
 * nothing here rounds a saturated second down to a quiet-looking one.
 *
 * The window only ever looks backwards, so a burst starts in the second it happened in and
 * is carried by the seconds after it. A window centred on its reading would draw part of the
 * burst into the seconds before it -- traffic at a time nothing was moving.
 */
export function smooth(readings: readonly Reading[]): Reading[] {
  let drawn: readonly Reading[] = readings
  for (let pass = 0; pass < PASSES; pass++) drawn = runningMean(drawn, SPAN)
  return [...drawn]
}

/** runningMean is one backward-looking pass: each reading averaged with the span - 1
 *  measured before it. */
function runningMean(readings: readonly Reading[], span: number): Reading[] {
  // The readings still inside the window, oldest first. Never longer than the span, so the
  // shift below is over a handful of numbers rather than the whole series.
  const window: number[] = []

  return readings.map((reading) => {
    // A gap is an interval nothing was measured in, so it ends the run: the reading after it
    // starts the window again rather than being averaged with a rate from before a stretch
    // of time the agent cannot account for.
    if (reading === null) {
      window.length = 0
      return null
    }

    window.push(reading)
    if (window.length > span) window.shift()

    // Divided by what the window actually holds, not by the span. The first seconds of a run
    // have fewer than span readings behind them, and dividing by the span there would draw
    // them at a fraction of the rate they were measured at.
    let total = 0
    for (const value of window) total += value
    return total / window.length
  })
}
