// SPDX-License-Identifier: MIT

import { areaPoints, points, runs, type Plot, type Reading } from './geometry'

/** SeriesSpec is one line on a chart. `fill` and `dashed` are second channels: two series
 *  told apart by hue alone is the one thing this codebase never does. */
export interface SeriesSpec {
  id: string
  label: string
  values: readonly Reading[]
  fill?: boolean | undefined
  dashed?: boolean | undefined
  /** tone picks a line out of the indexed palette, for a chart whose series are named by
   *  the data rather than by this code -- a device or a port has no CSS rule of its own.
   *  Each tone carries its own dash pattern as well as its own hue, so the eight lines are
   *  still told apart on a monochrome screen. */
  tone?: number | undefined
  /** detail qualifies an ambiguous label in the legend: two connections can both carry a
   *  port 443, and the number alone does not say which. */
  detail?: string | undefined
  /** muted draws the line as a background quantity rather than as one of the named ones,
   *  for the series standing for everything a chart did not name. */
  muted?: boolean | undefined
}

/** TONES is how many indexed lines the palette defines. A chart with more series than this
 *  reuses tones, which is why the breakdown names eight and folds the rest. */
export const TONES = 8

/** Mark is what a line, its legend swatch and its tooltip swatch all have to draw the same
 *  way. They are three views of one series, so they take one description of its appearance
 *  rather than each deriving one. */
export interface Mark {
  tone?: number | undefined
  muted?: boolean | undefined
}

/** markClass is the palette class for a series, empty for one with a rule of its own. */
export function markClass(mark: Mark): string {
  const classes: string[] = []
  if (mark.tone !== undefined) classes.push(`tone-${((mark.tone % TONES) + TONES) % TONES}`)
  if (mark.muted) classes.push('muted')
  return classes.join(' ')
}

/** Series draws one series: a line per measured run, and the area under it when asked.
 *  The class carries the series id, so the palette lives in CSS and a test can find the
 *  line it means without counting elements. The area's gradient is the series' own,
 *  painted in the colour the class gives it, so a filled line and its fill never differ. */
export function Series({
  series,
  plot,
  fillId,
}: {
  series: SeriesSpec
  plot: Plot
  /** fillId is the chart's own prefix for the gradient this series paints its area with;
   *  without one the area is left out even for a filled series, because a flat block
   *  hides the line under it. */
  fillId?: string | undefined
}) {
  const gradientId = fillId === undefined ? undefined : `${fillId}-${series.id}`
  const filled = series.fill === true && gradientId !== undefined
  return (
    <g className={`chart-series ${series.id} ${markClass(series)}`.trimEnd()}>
      {filled ? (
        <defs>
          <linearGradient id={gradientId} x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" className="chart-fill-top" />
            <stop offset="100%" className="chart-fill-bottom" />
          </linearGradient>
        </defs>
      ) : null}
      {runs(series.values).map((run, index) => (
        <g key={`${series.id}-${index}`} className="chart-run">
          {filled && run.length > 1 ? (
            <polygon
              className="chart-area"
              fill={`url(#${gradientId})`}
              points={areaPoints(run, plot)}
            />
          ) : null}
          <polyline
            className={series.dashed ? 'chart-line dashed' : 'chart-line'}
            points={points(run, plot)}
            vectorEffect="non-scaling-stroke"
          />
        </g>
      ))}
    </g>
  )
}
