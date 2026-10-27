// SPDX-License-Identifier: MIT

import { useId, useState } from 'react'

import { ValueAxis, TimeAxis } from './Axis'
import { ChartLegend, type LegendEntry } from './ChartLegend'
import { ChartTooltip, type TooltipRow } from './ChartTooltip'
import { Crosshair, HoverColumns } from './Crosshair'
import { columnsIn, peak, plotFor, PLOT_H, PLOT_W } from './geometry'
import { Grid } from './Grid'
import { Series, type SeriesSpec } from './Series'
import { elapsedTicks, formatElapsed, niceMax, valueTicks } from './scale'

/** What a series read at a column, or nothing when that interval was never measured. */
function readingAt(series: SeriesSpec, at: number): number | null {
  return series.values[at] ?? null
}

/** The most recent measured reading, which is what the legend carries. Reading the last
 *  column outright would report "not measured" every time one sample was missed. */
function latest(series: SeriesSpec): number | null {
  for (let at = series.values.length - 1; at >= 0; at -= 1) {
    const value = series.values[at]
    if (value !== null && value !== undefined) return value
  }
  return null
}

/**
 * A chart of measurements over time: axes, a grid, a line per series, and the figure
 * under the pointer.
 *
 * The pointed-at column can be handed in, which is what makes the tooltip testable without
 * simulating a pixel; left out, the chart keeps it itself and a pointer is what moves it.
 */
export function TimeSeriesChart({
  series,
  summary,
  format,
  intervalSec,
  max,
  hoverIndex,
  onHover,
}: {
  series: readonly SeriesSpec[]
  /** summary is what a screen reader is told instead of the geometry. */
  summary: string
  /** format writes a reading the way this chart's axis, legend and tooltip all say it, so
   *  one chart never labels the same number two ways. */
  format: (value: number) => string
  /** intervalSec is how far apart two columns are. The time axis is built from it, so a
   *  chart drawn at the wrong cadence says so rather than looking right. */
  intervalSec: number
  /** max pins the vertical scale when the caller knows it, e.g. to make two charts share
   *  one. Left out, the chart rounds its own largest reading up to a readable step. */
  max?: number | undefined
  hoverIndex?: number | undefined
  onHover?: ((at: number | undefined) => void) | undefined
}) {
  // Each series paints its own area gradient under this prefix, so two charts on one
  // page never share an id and a chart never paints one series with another's colour.
  const gradientId = useId()
  const [ownHover, setOwnHover] = useState<number | undefined>(undefined)
  const at = hoverIndex ?? ownHover
  const hover = onHover ?? setOwnHover

  const columns = columnsIn(series)
  const top = max !== undefined && max > 0 ? max : niceMax(peak(series))
  const plot = plotFor(columns, top)

  const values = valueTicks(top, format)
  const times = elapsedTicks(columns, intervalSec)

  const legend: LegendEntry[] = series.map((s) => {
    const value = latest(s)
    return {
      id: s.id,
      label: s.label,
      value: value === null ? 'not measured' : format(value),
      tone: s.tone,
      muted: s.muted,
      detail: s.detail,
    }
  })

  const rows: TooltipRow[] =
    at === undefined
      ? []
      : series.map((s) => {
          const value = readingAt(s, at)
          return {
            id: s.id,
            label: s.label,
            value: value === null ? 'not measured' : format(value),
            tone: s.tone,
            muted: s.muted,
          }
        })

  const agoSec = at === undefined ? 0 : (columns - 1 - at) * intervalSec

  return (
    <div className="chart">
      <div className="chart-frame">
        <ValueAxis ticks={values} />
        <div className="chart-plot-area">
          <svg
            className="chart-plot"
            viewBox={`0 0 ${PLOT_W} ${PLOT_H}`}
            preserveAspectRatio="none"
            aria-hidden="true"
            focusable="false"
          >
            <Grid ticks={values} />

            {series.map((s) => (
              <Series key={s.id} series={s} plot={plot} fillId={gradientId} />
            ))}

            {at === undefined ? null : <Crosshair plot={plot} at={at} series={series} />}

            <HoverColumns plot={plot} onHover={hover} />
          </svg>

          {at === undefined ? null : (
            <ChartTooltip
              fraction={plot.fraction(at)}
              when={agoSec === 0 ? 'now' : `${formatElapsed(agoSec)} ago`}
              rows={rows}
            />
          )}
        </div>
      </div>

      <TimeAxis ticks={times} />
      <ChartLegend entries={legend} />

      {/* The geometry above is decorative; this is what the chart actually says. Every
          figure in it is printed as text beside the chart too, so nothing here is the
          only copy of anything. */}
      <span className="sr-only">{summary}</span>
    </div>
  )
}
