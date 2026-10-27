// SPDX-License-Identifier: MIT

import { percent } from './geometry'
import type { Tick } from './scale'

// Both axes are HTML laid over and under the drawing rather than text inside it. The plot
// is stretched by CSS without preserving its aspect ratio, so any text in it would be
// stretched with it -- and text in the DOM is text a test can read back.
//
// They are hidden from a screen reader for the same reason the drawing is: an axis is
// only useful next to the shape it scales, and the chart's summary states the figures in
// a sentence instead.

/** ValueAxis is the vertical scale: what a height on this chart is worth. */
export function ValueAxis({ ticks }: { ticks: readonly Tick[] }) {
  return (
    <div className="chart-axis-y" aria-hidden="true">
      {ticks.map((tick) => (
        <span className="chart-tick" key={tick.fraction} style={{ bottom: percent(tick.fraction) }}>
          {tick.label}
        </span>
      ))}
    </div>
  )
}

/** TimeAxis is the horizontal scale: how far back the left-hand edge reaches. */
export function TimeAxis({ ticks }: { ticks: readonly Tick[] }) {
  return (
    <div className="chart-axis-x" aria-hidden="true">
      {ticks.map((tick) => (
        <span className="chart-tick" key={tick.fraction} style={{ left: percent(tick.fraction) }}>
          {tick.label}
        </span>
      ))}
    </div>
  )
}
