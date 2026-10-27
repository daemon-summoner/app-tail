// SPDX-License-Identifier: MIT

import { PLOT_H, PLOT_W, type Plot } from './geometry'
import { markClass, type SeriesSpec } from './Series'

/** Crosshair marks the column a reader is pointing at, so the tooltip's figures and the
 *  place they were read from are visibly the same column. A dot sits on each line at
 *  that column, in the line's own colour, for the readings the tooltip carries. */
export function Crosshair({
  plot,
  at,
  series,
}: {
  plot: Plot
  at: number
  series: readonly SeriesSpec[]
}) {
  const x = plot.x(at)
  return (
    <g className="chart-crosshair-layer">
      <line
        className="chart-crosshair"
        x1={x}
        x2={x}
        y1="0"
        y2={PLOT_H}
        vectorEffect="non-scaling-stroke"
      />
      {series.map((s) => {
        const value = s.values[at]
        if (value === null || value === undefined) return null
        const y = plot.y(value)
        return (
          // A zero-length line with round caps is a dot whose size does not stretch with
          // the plot, which a circle in this coordinate space would.
          <line
            key={s.id}
            className={`chart-reading ${s.id} ${markClass(s)}`.trimEnd()}
            x1={x}
            x2={x}
            y1={y}
            y2={y}
            vectorEffect="non-scaling-stroke"
          />
        )
      })}
    </g>
  )
}

/**
 * HoverColumns is the surface a pointer actually hits: one transparent band per column,
 * each reporting its own index.
 *
 * A single band plus arithmetic on the pointer's position would mean measuring the
 * element, which no chart here does -- and a test with no layout engine could never
 * exercise it. A band per column is the same interaction with the geometry left to the
 * browser, and a test hovers a column directly.
 *
 * Pointing is an extra rather than the only way to read a figure: the legend carries the
 * current value of every series in text, and the summary states the reading in a sentence,
 * so nothing here is reachable by hover alone.
 */
export function HoverColumns({
  plot,
  onHover,
}: {
  plot: Plot
  onHover: (at: number | undefined) => void
}) {
  const width = PLOT_W / plot.columns
  return (
    <g className="chart-hover" onMouseLeave={() => onHover(undefined)}>
      {Array.from({ length: plot.columns }, (_unused, at) => (
        <rect
          key={at}
          x={Math.max(0, plot.x(at) - width / 2)}
          y="0"
          width={width}
          height={PLOT_H}
          fill="transparent"
          onMouseEnter={() => onHover(at)}
        />
      ))}
    </g>
  )
}
