// SPDX-License-Identifier: MIT

import { percent } from './geometry'
import { markClass, type Mark } from './Series'

/** One line of a tooltip: which series, and what it read there. The mark matches the line's
 *  own, so the swatch beside a reading is the same one the legend carries. */
export interface TooltipRow extends Mark {
  id: string
  label: string
  value: string
}

/**
 * ChartTooltip reports the column under the pointer.
 *
 * HTML rather than an SVG foreignObject or text: the plot is stretched, and anything
 * inside it stretches with it. Positioned as a percentage of the plot's width from the
 * same fraction the crosshair is drawn at, so the two cannot point at different columns.
 */
export function ChartTooltip({
  fraction,
  when,
  rows,
}: {
  fraction: number
  /** when says which moment the figures are from, because a chart of the last few minutes
   *  is read by asking "when was that". */
  when: string
  rows: readonly TooltipRow[]
}) {
  // Past the halfway mark the box is flipped to the other side of the crosshair, so a
  // reading near the right-hand edge is not drawn off the end of the chart.
  const flipped = fraction > 0.5
  return (
    <div
      className={flipped ? 'chart-tooltip flipped' : 'chart-tooltip'}
      style={{ left: percent(fraction) }}
      role="status"
    >
      <span className="chart-tooltip-when">{when}</span>
      {rows.map((row) => (
        <span className={`chart-tooltip-row ${row.id} ${markClass(row)}`.trimEnd()} key={row.id}>
          <span className="chart-swatch" aria-hidden="true" />
          <span className="chart-tooltip-label">{row.label}</span>
          <span className="chart-tooltip-value">{row.value}</span>
        </span>
      ))}
    </div>
  )
}
