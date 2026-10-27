// SPDX-License-Identifier: MIT

import { PLOT_H, PLOT_W } from './geometry'
import type { Tick } from './scale'

/** Grid draws the line each axis label is read against. It is given the same ticks the
 *  labels are built from, so a reader lining a peak up with "1 MB/s" is looking at the
 *  line that means it. */
export function Grid({ ticks }: { ticks: readonly Tick[] }) {
  return (
    <g className="chart-grid">
      {ticks.map((tick) => {
        const y = PLOT_H - tick.fraction * PLOT_H
        return (
          <line
            key={tick.fraction}
            x1="0"
            x2={PLOT_W}
            y1={y}
            y2={y}
            vectorEffect="non-scaling-stroke"
          />
        )
      })}
    </g>
  )
}
