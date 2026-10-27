// SPDX-License-Identifier: MIT

// Where the lines and the labels go.
//
// A chart with no axis is a shape; the axis is what makes it a measurement. Both the
// gridlines in the drawing and the labels in the HTML beside it are built from the same
// ticks, so the number a reader sees and the line they read it against cannot drift apart.

/** A place on an axis: what it is worth, where it sits as 0..1, and what it is called. */
export interface Tick {
  value: number
  fraction: number
  label: string
}

/** The steps a rounded axis maximum is allowed to take, per power of ten. 1, 2 and 5 are
 *  the divisions people read without arithmetic; 3 or 7 make a reader do sums. */
const STEPS = [1, 2, 2.5, 5, 10]

/**
 * niceMax rounds an observed peak up to a value an axis can be divided evenly by.
 *
 * A chart scaled to exactly its largest reading puts that reading on the top edge and
 * labels the axis with whatever number it happened to be. Rounding up gives the axis
 * round numbers and leaves the peak visibly below the top, which is also how a reader
 * tells a peak from a clipped one.
 */
export function niceMax(value: number): number {
  if (!Number.isFinite(value) || value <= 0) return 1
  const magnitude = 10 ** Math.floor(Math.log10(value))
  const scaled = value / magnitude
  const step = STEPS.find((candidate) => scaled <= candidate) ?? 10
  return step * magnitude
}

/**
 * valueTicks divides a vertical axis into evenly spaced labelled steps.
 *
 * The zero line is left out: it is the plot's own baseline, and labelling it costs a row
 * of text to say the chart starts at nothing, which every chart here does.
 */
export function valueTicks(top: number, format: (value: number) => string, count = 3): Tick[] {
  if (count < 1 || top <= 0) return []
  // What the formatter writes for nothing. A step it writes the same way is a line
  // labelled "0 B/s" a third of the way up the plot -- naming the baseline at a height
  // the baseline is not at, which misreads worse than one fewer line does.
  const nothing = format(0)
  const out: Tick[] = []
  for (let step = 1; step <= count; step += 1) {
    const fraction = step / count
    const value = top * fraction
    const label = format(value)
    if (label === nothing) continue
    // A scale finer than the figures are written at labels two steps identically -- an
    // axis topping out at two connections writes "1" twice -- which is one line a reader
    // can use and one that says nothing. The higher of the pair is kept, so the top of the
    // scale is always labelled and the axis loses a line rather than repeating one.
    if (out[out.length - 1]?.label === label) out.pop()
    out.push({ value, fraction, label })
  }
  return out
}

/**
 * elapsedTicks labels a horizontal axis of samples that end at now.
 *
 * The labels say how long ago, not what the clock said: this window is minutes long and
 * lives beside a figure for right now, so "2m ago" is what a reader is actually asking.
 * The right-hand end is named rather than numbered, because zero seconds ago is now.
 */
export function elapsedTicks(columns: number, intervalSec: number, count = 4): Tick[] {
  if (columns < 2 || intervalSec <= 0 || count < 1) return []
  const spanSec = (columns - 1) * intervalSec
  // A window shorter than the labels asked for cannot fill them: every label rounds to the
  // same second and the axis reads "1s ago" three times over. Fewer labels is the honest
  // picture of a short window.
  const steps = Math.min(count, Math.max(1, Math.floor(spanSec)))
  const out: Tick[] = []
  for (let step = 0; step <= steps; step += 1) {
    const fraction = step / steps
    const agoSec = Math.round(spanSec * (1 - fraction))
    const label = agoSec === 0 ? 'now' : `${formatElapsed(agoSec)} ago`
    // Whole units mean two places on a 90-second axis are both "1m ago". The earlier one
    // is kept, because the left-hand end is what says how far back the window reaches.
    if (out[out.length - 1]?.label === label) continue
    out.push({ value: agoSec, fraction, label })
  }
  return out
}

/** formatElapsed writes a duration the way the axis has room for: whole units, one term. */
export function formatElapsed(seconds: number): string {
  if (seconds < 60) return `${Math.round(seconds)}s`
  if (seconds < 3600) return `${Math.round(seconds / 60)}m`
  if (seconds < 86_400) return `${Math.round(seconds / 3600)}h`
  return `${Math.round(seconds / 86_400)}d`
}
