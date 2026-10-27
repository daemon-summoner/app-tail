// SPDX-License-Identifier: MIT

// Turning one breakdown lane into the lines a chart draws.
//
// Kept apart from the components because this is where the decisions are -- which keys are
// worth a line, which tone each gets, what a filtered chart still contains -- and every one
// of them is testable as a function of a payload rather than of a rendered tree.

import type { TrafficBreakdown, TrafficSeries } from '../../api'
import type { Reading } from '../charts/geometry'
import type { SeriesSpec } from '../charts/Series'
import { smooth } from '../charts/smooth'

/** The key the agent gives the line standing for everything it did not name. It is folded
 *  last on the chart and never filtered away, or a filtered view would silently lose the
 *  traffic the cap left unnamed. */
export const OTHER_KEY = '__other__'

/** A filter over a breakdown: a connection, a device, or neither. Both are ids rather than
 *  labels, because a label is not unique and two tailnets can hold a device of one name. */
export interface BreakdownFilter {
  via?: string | undefined
  peer?: string | undefined
}

/** matches decides whether one series survives a filter.
 *
 * A series that names neither a connection nor a device -- the folded line, and rows from a
 * seam that has no such handle -- is kept under every filter. It is the one place the
 * missing traffic could be, so dropping it would make a filtered chart claim to be complete
 * when it is not. */
export function matches(series: TrafficSeries, filter: BreakdownFilter): boolean {
  if (series.key === OTHER_KEY) return true
  if (filter.via !== undefined && series.via !== filter.via) return false
  if (filter.peer !== undefined && series.peer !== filter.peer) return false
  return true
}

/** Which direction of a series a chart is drawing. */
export type Direction = 'up' | 'down'

/**
 * linesFor turns the surviving series into chart lines in one direction.
 *
 * Tones are assigned from the breakdown's own order, which is busiest first, and are shared
 * across the two directions by index: the same key has to be the same line on both charts,
 * or reading an upload against the download that answered it is guesswork.
 */
export function linesFor(
  series: readonly TrafficSeries[],
  direction: Direction,
  smoothed: boolean,
): SeriesSpec[] {
  return series.map((s, index) => {
    const values: Reading[] = (direction === 'up' ? s.up : s.down).map((v) => v ?? null)
    const line: SeriesSpec = {
      id: s.key,
      label: s.label,
      detail: s.detail,
      values: smoothed ? smooth(values) : values,
    }
    // The folded line is not one of the named eight and must not wear one of their marks:
    // it is drawn muted, which is also what says it stands for keys nobody chose.
    if (s.key === OTHER_KEY) return { ...line, muted: true }
    return { ...line, tone: index }
  })
}

/** Whether a breakdown holds anything worth drawing. Two measured columns is the minimum a
 *  line can be read from, and a lane whose every key is a flat absence draws as nothing. */
export function hasReadings(series: readonly TrafficSeries[]): boolean {
  return series.some(
    (s) =>
      s.up.filter((v) => v !== null).length >= 2 || s.down.filter((v) => v !== null).length >= 2,
  )
}

/** One choice in a filter: the id the series carry, and the name a person reads. */
export interface FilterOption {
  id: string
  label: string
}

/**
 * optionsFor collects the distinct connections or devices the rows actually name, so a
 * filter never offers a choice that would empty the chart.
 *
 * Names come from `labels` where it has one, since the rows carry ids: a device the peer
 * list has since forgotten still has to be selectable, so its own id is the fallback rather
 * than the row being left out.
 */
export function optionsFor(
  series: readonly TrafficSeries[],
  field: 'via' | 'peer',
  labels: ReadonlyMap<string, string>,
): FilterOption[] {
  const seen = new Map<string, string>()
  for (const s of series) {
    const id = s[field]
    if (id === undefined || id === '' || seen.has(id)) continue
    seen.set(id, labels.get(id) ?? id)
  }
  return [...seen]
    .map(([id, label]) => ({ id, label }))
    .sort((a, b) => a.label.localeCompare(b.label))
}

/** total is what one direction of a breakdown reads at its most recent measured column,
 *  which is the figure the headline beside the chart states. */
export function total(series: readonly TrafficSeries[], direction: Direction): number {
  let sum = 0
  for (const s of series) {
    const values = direction === 'up' ? s.up : s.down
    for (let at = values.length - 1; at >= 0; at -= 1) {
      const value = values[at]
      if (value !== null && value !== undefined) {
        sum += value
        break
      }
    }
  }
  return sum
}

/** visible is the series a chart draws: what survives the filter, kept in the agent's own
 *  busiest-first order so the tones run from the busiest line down whether or not a filter
 *  is on. */
export function visible(
  breakdown: TrafficBreakdown | undefined,
  filter: BreakdownFilter,
): TrafficSeries[] {
  if (breakdown === undefined) return []
  return breakdown.series.filter((s) => matches(s, filter))
}
