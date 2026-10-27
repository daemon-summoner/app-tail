// SPDX-License-Identifier: MIT

// The rules every chart in this directory is built on.
//
// 1. Never measure. Each plot is drawn in a fixed coordinate space with
//    preserveAspectRatio="none" and stretched by CSS. Nothing calls
//    getBoundingClientRect or observes a resize, so a chart is a pure function of its
//    props -- which is what lets a test with no layout engine assert on what it drew.
// 2. Every tick, legend entry and tooltip value is a real text node, in HTML rather than
//    inside the stretched SVG: text in a non-uniformly scaled drawing comes out distorted,
//    and text a test cannot read is a figure nobody can check.
// 3. Geometry lives in numeric attributes -- points, x, y, width -- never in a curved path
//    string. A test reads `points` back as numbers; it cannot read a bezier.
// 4. The drawing is aria-hidden and carries a written summary beside it. The shape is not
//    information a screen reader can use; the sentence is.
// 5. Interaction is a controlled prop. The hovered column is passed in, so a tooltip test
//    sets an index and asserts on text rather than simulating a pixel.

/** A value the agent could not measure. A gap breaks the line rather than dropping to
 *  zero: "nothing moved" and "nobody looked" are different statements, and drawing the
 *  second as the first invents a quiet period that never happened. */
export type Reading = number | null

/** The coordinate space a plot is drawn in. CSS stretches it; strokes opt out of scaling
 *  so they stay the same weight at any size. */
export const PLOT_W = 600
export const PLOT_H = 120

/** A measured reading and the column it belongs to. */
export interface Sample {
  at: number
  value: number
}

/** runs splits a series at its gaps, so each stretch of measured values is drawn as its
 *  own line and nothing is drawn across the gap between them. */
export function runs(values: readonly Reading[]): Sample[][] {
  const out: Sample[][] = []
  let current: Sample[] = []
  values.forEach((value, at) => {
    if (value === null) {
      if (current.length > 0) out.push(current)
      current = []
      return
    }
    current.push({ at, value })
  })
  if (current.length > 0) out.push(current)
  return out
}

/** columnsIn is how many slots the horizontal axis is divided into. Never fewer than two:
 *  one column has no width to divide by, and a partly-filled window should draw at the
 *  scale the full one will rather than stretch a handful of samples across it. */
export function columnsIn(series: readonly { values: readonly Reading[] }[]): number {
  return Math.max(2, ...series.map((s) => s.values.length))
}

/** peak is the largest reading across every series, and never zero: an all-quiet chart
 *  still has to divide by something, and a flat line along the bottom is the right
 *  picture for a machine carrying nothing. */
export function peak(
  series: readonly { values: readonly Reading[] }[],
  override?: number,
): number {
  if (override !== undefined && override > 0) return override
  let top = 0
  for (const s of series) {
    for (const value of s.values) {
      if (value !== null && value > top) top = value
    }
  }
  return top > 0 ? top : 1
}

/** Plot is the mapping from a reading to a place in the drawing. Both charts and the
 *  things drawn over them -- grid, crosshair, hover columns -- take the same one, so an
 *  overlay cannot land somewhere the line is not. */
export interface Plot {
  columns: number
  top: number
  x: (at: number) => number
  y: (value: number) => number
  /** fraction is the horizontal position of a column as 0..1, which is what the HTML
   *  layers over the drawing are positioned with. */
  fraction: (at: number) => number
}

export function plotFor(columns: number, top: number): Plot {
  const span = columns - 1
  return {
    columns,
    top,
    x: (at) => (at / span) * PLOT_W,
    y: (value) => PLOT_H - (value / top) * PLOT_H,
    fraction: (at) => at / span,
  }
}

/** points renders a run as the `points` attribute of a polyline or polygon. */
export function points(run: readonly Sample[], plot: Plot): string {
  return run.map((sample) => `${plot.x(sample.at)},${plot.y(sample.value)}`).join(' ')
}

/** areaPoints closes a run down to the baseline, which is what fills the space under it. */
export function areaPoints(run: readonly Sample[], plot: Plot): string {
  const first = run[0]
  const last = run[run.length - 1]
  if (first === undefined || last === undefined) return ''
  return `${plot.x(first.at)},${PLOT_H} ${points(run, plot)} ${plot.x(last.at)},${PLOT_H}`
}

/** percent is how every HTML layer over a plot is positioned. Kept here so the drawing
 *  and the text over it round the same way. */
export function percent(fraction: number): string {
  return `${(fraction * 100).toFixed(4)}%`
}
