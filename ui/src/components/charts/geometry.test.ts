// SPDX-License-Identifier: MIT

import { describe, expect, it } from 'vitest'

import {
  areaPoints,
  columnsIn,
  peak,
  percent,
  plotFor,
  points,
  PLOT_H,
  PLOT_W,
  runs,
} from './geometry'

describe('splitting a series at its gaps', () => {
  // A gap means the interval was never measured. Keeping the readings either side in one
  // run would draw a line straight across it, inventing a quiet period that nobody saw.
  it('starts a new run after every gap and keeps each reading in its own column', () => {
    expect(runs([5, null, 7, 9])).toEqual([
      [{ at: 0, value: 5 }],
      [
        { at: 2, value: 7 },
        { at: 3, value: 9 },
      ],
    ])
  })

  it('produces no runs at all for a series that was never measured', () => {
    expect(runs([null, null])).toEqual([])
  })

  // A trailing run is only closed at the end of the loop. Forgetting that flush drops the
  // most recent readings, which is the half of the chart anyone is actually looking at.
  it('keeps the readings after the last gap', () => {
    expect(runs([null, 1, 2])).toEqual([
      [
        { at: 1, value: 1 },
        { at: 2, value: 2 },
      ],
    ])
  })
})

describe('how many columns a chart is divided into', () => {
  it('takes the longest series, so a shorter one does not shrink the axis', () => {
    expect(columnsIn([{ values: [1, 2] }, { values: [1, 2, 3, 4] }])).toBe(4)
  })

  // One column has no width to divide by: every x coordinate comes out of a division by
  // zero and the chart renders empty with nothing to explain it.
  it('never falls below two columns, however few readings there are', () => {
    expect(columnsIn([{ values: [1] }])).toBe(2)
    expect(columnsIn([])).toBe(2)
  })
})

describe('the top of the scale', () => {
  it('is the largest reading across every series', () => {
    expect(peak([{ values: [1, 9] }, { values: [4, null] }])).toBe(9)
  })

  // Same reason as the column floor: an all-quiet machine still has to divide by
  // something, and a flat line along the bottom is the right picture for one.
  it('is never zero, so a quiet machine draws a flat line rather than NaN', () => {
    expect(peak([{ values: [0, 0] }])).toBe(1)
    expect(peak([{ values: [null] }])).toBe(1)
  })

  it('takes a pinned maximum when one is given, so two charts can share a scale', () => {
    expect(peak([{ values: [1, 2] }], 100)).toBe(100)
  })

  // A pinned zero is not a scale, it is a division by zero wearing a caller's clothes.
  it('ignores a pinned maximum of zero and measures the readings instead', () => {
    expect(peak([{ values: [1, 7] }], 0)).toBe(7)
  })
})

describe('placing a reading in the drawing', () => {
  it('spreads the columns across the full width, first at the left edge and last at the right', () => {
    const plot = plotFor(3, 10)
    expect(plot.x(0)).toBe(0)
    expect(plot.x(2)).toBe(PLOT_W)
  })

  // SVG's y axis grows downwards, so a bigger reading has to be a smaller y. Getting this
  // backwards draws an upside-down chart that still looks like a chart.
  it('puts the top of the scale at the top of the plot and zero on the baseline', () => {
    const plot = plotFor(3, 10)
    expect(plot.y(10)).toBe(0)
    expect(plot.y(0)).toBe(PLOT_H)
  })

  // The HTML layers over the plot -- ticks, crosshair label, tooltip -- are positioned
  // from this fraction while the drawing uses x(). If the two disagreed, the tooltip would
  // point at a different column from the one it is reporting.
  it('reports a column as the same fraction across that the drawing places it at', () => {
    const plot = plotFor(5, 10)
    expect(plot.fraction(2)).toBeCloseTo(plot.x(2) / PLOT_W, 10)
  })
})

describe('what gets written into the drawing', () => {
  it('writes a run as plain x,y pairs a test can read back as numbers', () => {
    const plot = plotFor(3, 10)
    expect(
      points(
        [
          { at: 0, value: 0 },
          { at: 2, value: 10 },
        ],
        plot,
      ),
    ).toBe(`0,${PLOT_H} ${PLOT_W},0`)
  })

  // The area is the same line closed down to the baseline at both ends. Without those two
  // extra corners the polygon closes diagonally across the plot instead of under the line.
  it('closes a filled run down to the baseline at both ends', () => {
    const plot = plotFor(3, 10)
    const area = areaPoints(
      [
        { at: 0, value: 5 },
        { at: 1, value: 10 },
      ],
      plot,
    )
    expect(area.startsWith(`0,${PLOT_H} `)).toBe(true)
    expect(area.endsWith(` ${plot.x(1)},${PLOT_H}`)).toBe(true)
  })

  it('draws no area for a run with nothing in it', () => {
    expect(areaPoints([], plotFor(3, 10))).toBe('')
  })
})

// Every layer over the plot is positioned this way, so they all round identically. Two
// roundings would let the crosshair and its tooltip land a fraction of a column apart.
describe('positioning a layer over the plot', () => {
  it('writes a fraction as a percentage of the plot width', () => {
    expect(percent(0.5)).toBe('50.0000%')
    expect(percent(0)).toBe('0.0000%')
    expect(percent(1)).toBe('100.0000%')
  })
})
