// SPDX-License-Identifier: MIT

import { markClass, type Mark } from './Series'

/** One entry in a legend: a series, and what it reads right now. The mark is the line's
 *  own, so the swatch repeats both its hue and its dash pattern -- a legend that repeated
 *  only the hue would drop the second channel exactly where it is needed most. */
export interface LegendEntry extends Mark {
  id: string
  label: string
  value: string
  /** detail qualifies a label that would otherwise be ambiguous -- which connection a port
   *  belongs to, how a device is reached. Left out where the label stands alone. */
  detail?: string | undefined
}

/**
 * ChartLegend names every series and carries its current figure as text.
 *
 * It is not decoration for the chart: it is the only place the numbers are readable
 * without pointing at anything, which is what keeps a chart whose detail is behind a
 * hover from being unreadable with a keyboard.
 */
export function ChartLegend({ entries }: { entries: readonly LegendEntry[] }) {
  return (
    <div className="chart-legend">
      {entries.map((entry) => (
        <span
          className={`chart-legend-item ${entry.id} ${markClass(entry)}`.trimEnd()}
          key={entry.id}
        >
          <span className="chart-swatch" aria-hidden="true" />
          <span className="chart-legend-label">{entry.label}</span>
          {entry.detail ? <span className="chart-legend-detail">{entry.detail}</span> : null}
          <span className="chart-legend-value">{entry.value}</span>
        </span>
      ))}
    </div>
  )
}
