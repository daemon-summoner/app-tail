// SPDX-License-Identifier: MIT

import { fireEvent } from '@testing-library/react'
import { describe, expect, it } from 'vitest'

import { renderScoped } from '../../test/agent'
import { PLOT_H } from './geometry'
import { TimeSeriesChart } from './TimeSeriesChart'
import type { SeriesSpec } from './Series'

/** The plotted points of the nth line, as numbers, so a test asserts on the shape drawn
 *  rather than on a formatted string. */
function pointsOf(container: HTMLElement, index = 0): { x: number; y: number }[] {
  const lines = container.querySelectorAll('polyline')
  const line = lines[index]
  if (!line) throw new Error(`no line at index ${index}; the chart drew ${lines.length}`)
  return (line.getAttribute('points') ?? '')
    .split(' ')
    .filter(Boolean)
    .map((pair) => {
      const [x, y] = pair.split(',').map(Number)
      return { x: x ?? 0, y: y ?? 0 }
    })
}

function chart(props: {
  series: readonly SeriesSpec[]
  max?: number
  hoverIndex?: number
  onHover?: (at: number | undefined) => void
}) {
  return renderScoped(
    <TimeSeriesChart
      summary="test"
      format={(value) => `${value} B/s`}
      intervalSec={1}
      {...props}
    />,
  )
}

describe('what the chart plots', () => {
  it('draws one point per reading, left to right', () => {
    const view = chart({ series: [{ id: 'up', label: 'Up', values: [0, 5, 10] }] })

    const points = pointsOf(view.container)
    expect(points).toHaveLength(3)
    expect(points[0]!.x).toBe(0)
    expect(points[2]!.x).toBeGreaterThan(points[1]!.x)
  })

  // The y axis is inverted in SVG, so a bigger reading has to be a smaller y. Getting
  // this backwards draws a chart that is upside down and still looks like a chart.
  it('puts a larger reading higher up', () => {
    const view = chart({ series: [{ id: 'up', label: 'Up', values: [1, 100] }] })

    const points = pointsOf(view.container)
    expect(points[1]!.y).toBeLessThan(points[0]!.y)
  })

  // An all-quiet machine still has to divide by something. Without a floor this is a
  // division by zero and every coordinate comes out NaN, which renders as an empty chart
  // with no error anywhere to explain it.
  it('draws a flat line rather than dividing by zero when nothing moved', () => {
    const view = chart({ series: [{ id: 'up', label: 'Up', values: [0, 0, 0] }] })

    const points = pointsOf(view.container)
    expect(points).toHaveLength(3)
    for (const p of points) {
      expect(Number.isNaN(p.y)).toBe(false)
    }
  })

  it('takes a pinned maximum so two charts can share a scale', () => {
    const view = chart({ max: 100, series: [{ id: 'up', label: 'Up', values: [50] }] })

    // Half of the pinned maximum sits at the vertical middle, not at the top.
    expect(pointsOf(view.container)[0]!.y).toBeCloseTo(PLOT_H / 2, 0)
  })

  // Scaling to the exact peak puts it on the top edge, where a reading that was clipped
  // off the chart looks the same as one that was not.
  it('scales to a rounded maximum, leaving the peak below the top edge', () => {
    const view = chart({ series: [{ id: 'up', label: 'Up', values: [0, 30] }] })

    expect(pointsOf(view.container)[1]!.y).toBeGreaterThan(0)
  })
})

// A gap means the interval could not be measured, not that nothing crossed. Drawing
// through it invents a quiet period; dropping it to zero invents an idle machine.
describe('a gap in the series', () => {
  it('breaks the line rather than drawing through it', () => {
    const view = chart({ series: [{ id: 'up', label: 'Up', values: [5, null, 7, 9] }] })

    const lines = view.container.querySelectorAll('polyline')
    expect(lines).toHaveLength(2)
    expect(pointsOf(view.container, 0)).toHaveLength(1)
    expect(pointsOf(view.container, 1)).toHaveLength(2)
  })

  it('leaves the readings either side in their own places on the axis', () => {
    const view = chart({ series: [{ id: 'up', label: 'Up', values: [5, null, 7] }] })

    const before = pointsOf(view.container, 0)[0]!
    const after = pointsOf(view.container, 1)[0]!
    // The gap occupies its own column: the reading after it is two columns along, not one.
    expect(after.x).toBeGreaterThan(before.x)
  })

  it('draws nothing at all for a series that is entirely gaps', () => {
    const view = chart({ series: [{ id: 'up', label: 'Up', values: [null, null] }] })

    expect(view.container.querySelectorAll('polyline')).toHaveLength(0)
  })
})

// Two series told apart by colour alone is the one thing this codebase never does. The
// fill and the dash are what make them distinguishable without it.
describe('telling two series apart', () => {
  const pair: SeriesSpec[] = [
    { id: 'up', label: 'Up', values: [1, 2], fill: true },
    { id: 'down', label: 'Down', values: [3, 4], dashed: true },
  ]

  it('gives each series its own line and its own name', () => {
    const view = chart({ series: pair })

    expect(view.container.querySelectorAll('polyline')).toHaveLength(2)
    expect(view.container.querySelector('.chart-series.up')).toBeInTheDocument()
    expect(view.container.querySelector('.chart-series.down')).toBeInTheDocument()
  })

  it('fills under one and dashes the other, so hue is not the only difference', () => {
    const view = chart({ series: pair })

    expect(view.container.querySelector('.chart-area')).toBeInTheDocument()
    expect(view.container.querySelector('.chart-line.dashed')).toBeInTheDocument()
  })
})

describe('the scale beside the drawing', () => {
  // The gridlines and the labels are built from one set of ticks. Two sets would let the
  // number a reader sees drift from the line they are reading it against.
  it('labels every gridline it draws', () => {
    const view = chart({ series: [{ id: 'up', label: 'Up', values: [0, 100] }] })

    const labels = view.container.querySelectorAll('.chart-axis-y .chart-tick')
    expect(view.container.querySelectorAll('.chart-grid line')).toHaveLength(labels.length)
    expect(labels[labels.length - 1]).toHaveTextContent('100 B/s')
  })

  // The interval is the agent's, not this component's: a window drawn at the wrong cadence
  // reports the wrong span and looks entirely correct doing it.
  it('says how far back the window reaches, at the interval it was measured at', () => {
    const view = renderScoped(
      <TimeSeriesChart
        summary="test"
        format={String}
        intervalSec={10}
        series={[{ id: 'up', label: 'Up', values: [1, 2, 3, 4, 5] }]}
      />,
    )

    const ticks = view.container.querySelectorAll('.chart-axis-x .chart-tick')
    expect(ticks[0]).toHaveTextContent('40s ago')
    expect(ticks[ticks.length - 1]).toHaveTextContent('now')
  })
})

describe('how a series is painted', () => {
  // The area under a filled line is painted with that series' own gradient, defined
  // inside its own group so it takes the series' colour. A gradient shared across the
  // chart would paint the download area in the upload colour.
  it('gives a filled series a gradient of its own, and an unfilled one none', () => {
    const view = chart({
      series: [
        { id: 'up', label: 'Up', values: [1, 2, 3], fill: true },
        { id: 'down', label: 'Down', values: [4, 5, 6] },
      ],
    })

    const up = view.container.querySelector('.chart-series.up')!
    const gradient = up.querySelector('linearGradient')!
    expect(gradient).not.toBeNull()
    expect(up.querySelector('.chart-area')).toHaveAttribute('fill', `url(#${gradient.id})`)

    const down = view.container.querySelector('.chart-series.down')!
    expect(down.querySelector('linearGradient')).toBeNull()
    expect(down.querySelector('.chart-area')).toBeNull()
  })

  it('keeps two charts on one page from sharing a gradient id', () => {
    const one = chart({ series: [{ id: 'up', label: 'Up', values: [1, 2], fill: true }] })
    const two = chart({ series: [{ id: 'up', label: 'Up', values: [1, 2], fill: true }] })

    const first = one.container.querySelector('linearGradient')!.id
    const second = two.container.querySelector('linearGradient')!.id
    expect(first).not.toBe(second)
  })
})

describe('reading a figure off the chart', () => {
  // The legend is the only place the numbers are readable without pointing at anything,
  // which is what keeps the chart from being unreadable with a keyboard.
  it('carries the latest measured value of every series as text', () => {
    const view = chart({
      series: [
        { id: 'up', label: 'Up', values: [1, 7] },
        { id: 'down', label: 'Down', values: [2, 9] },
      ],
    })

    expect(view.container.querySelector('.chart-legend-item.up')).toHaveTextContent('Up7 B/s')
    expect(view.container.querySelector('.chart-legend-item.down')).toHaveTextContent('Down9 B/s')
  })

  // One missed sample at the right-hand edge is normal. Reading the last column outright
  // would report a working chart as unmeasured every time one tick was dropped.
  it('reaches back past a missing final sample rather than reporting nothing', () => {
    const view = chart({ series: [{ id: 'up', label: 'Up', values: [4, null] }] })

    expect(view.container.querySelector('.chart-legend-item.up')).toHaveTextContent('Up4 B/s')
  })

  it('says a series was never measured rather than writing it as zero', () => {
    const view = chart({ series: [{ id: 'up', label: 'Up', values: [null, null] }] })

    expect(view.container.querySelector('.chart-legend-item.up')).toHaveTextContent(
      'Upnot measured',
    )
  })
})

describe('pointing at a column', () => {
  it('reports every series at that column, and when it was', () => {
    const view = chart({
      hoverIndex: 1,
      series: [
        { id: 'up', label: 'Up', values: [1, 2, 3] },
        { id: 'down', label: 'Down', values: [4, 5, 6] },
      ],
    })

    const tip = view.container.querySelector('.chart-tooltip')!
    expect(tip).toHaveTextContent('1s ago')
    expect(tip.querySelector('.chart-tooltip-row.up')).toHaveTextContent('Up2 B/s')
    expect(tip.querySelector('.chart-tooltip-row.down')).toHaveTextContent('Down5 B/s')
  })

  // Same rule as the line: an unmeasured interval is not a quiet one, and a tooltip that
  // writes it as zero is the chart stating a measurement nobody took.
  it('says an unmeasured column was not measured', () => {
    const view = chart({ hoverIndex: 1, series: [{ id: 'up', label: 'Up', values: [1, null] }] })

    expect(view.container.querySelector('.chart-tooltip-row.up')).toHaveTextContent(
      'Upnot measured',
    )
  })

  // The dot on each line is where the tooltip's figure was read from. It sits at the
  // line's own height there, and a line with no reading at that column gets none.
  it('marks the reading on each line at the pointed-at column', () => {
    const view = chart({
      hoverIndex: 1,
      series: [
        { id: 'up', label: 'Up', values: [1, 2, 3] },
        { id: 'down', label: 'Down', values: [4, null, 6] },
      ],
    })

    const dot = view.container.querySelector('.chart-reading.up')!
    expect(dot).not.toBeNull()
    expect(dot.getAttribute('x1')).toBe(dot.getAttribute('x2'))
    expect(Number(dot.getAttribute('y1'))).toBe(pointsOf(view.container)[1]!.y)
    expect(view.container.querySelector('.chart-reading.down')).toBeNull()
  })

  it('reports nothing until a column is pointed at', () => {
    const view = chart({ series: [{ id: 'up', label: 'Up', values: [1, 2] }] })

    expect(view.container.querySelector('.chart-tooltip')).toBeNull()
    expect(view.container.querySelector('.chart-crosshair')).toBeNull()
  })

  // The pointer lands on one transparent band per column, so which column was hit is the
  // browser's arithmetic rather than a measurement this component takes.
  it('hands the pointed-at column to its owner, so two charts can share one', () => {
    const seen: (number | undefined)[] = []
    const view = chart({
      onHover: (at) => seen.push(at),
      series: [{ id: 'up', label: 'Up', values: [1, 2, 3] }],
    })

    const bands = view.container.querySelectorAll('.chart-hover rect')
    expect(bands).toHaveLength(3)
    fireEvent.mouseEnter(bands[2]!)
    fireEvent.mouseLeave(view.container.querySelector('.chart-hover')!)
    expect(seen).toEqual([2, undefined])
  })

  // Anchored past the halfway mark, the box would be drawn off the right-hand end of the
  // chart, where the reading it is reporting cannot be read at all.
  it('flips the reading to the other side of the crosshair near the right-hand edge', () => {
    const left = chart({ hoverIndex: 0, series: [{ id: 'up', label: 'Up', values: [1, 2, 3] }] })
    const right = chart({ hoverIndex: 2, series: [{ id: 'up', label: 'Up', values: [1, 2, 3] }] })

    expect(left.container.querySelector('.chart-tooltip')).not.toHaveClass('flipped')
    expect(right.container.querySelector('.chart-tooltip')).toHaveClass('flipped')
  })
})

describe('what a screen reader is told', () => {
  // The geometry carries no information a screen reader can use, so it is hidden and the
  // sentence beside it is what the chart actually says.
  it('hides the drawing and carries the reading as text', () => {
    const view = renderScoped(
      <TimeSeriesChart
        summary="Upload 1.2 MB/s, download 340 KB/s over the last five minutes."
        format={String}
        intervalSec={1}
        series={[{ id: 'up', label: 'Up', values: [1, 2] }]}
      />,
    )

    expect(view.container.querySelector('svg')).toHaveAttribute('aria-hidden', 'true')
    expect(view.container.querySelector('.sr-only')).toHaveTextContent(
      'Upload 1.2 MB/s, download 340 KB/s over the last five minutes.',
    )
  })

  // An axis is only meaningful next to the shape it scales, so it is read out as neither
  // a list of numbers nor a second copy of the figures already in the summary.
  it('hides the axes too, leaving one sentence rather than a wall of tick labels', () => {
    const view = chart({ series: [{ id: 'up', label: 'Up', values: [1, 2] }] })

    expect(view.container.querySelector('.chart-axis-y')).toHaveAttribute('aria-hidden', 'true')
    expect(view.container.querySelector('.chart-axis-x')).toHaveAttribute('aria-hidden', 'true')
  })
})
