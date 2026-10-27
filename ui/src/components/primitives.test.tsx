// SPDX-License-Identifier: MIT

import { fireEvent } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'

import { makeForward, renderScoped } from '../test/agent'
import { DirectionBadge, Notice, ProtocolBadge, Route, StatusDot, Toggle, formatBytes, formatRate } from './primitives'

// These counters update on every poll, so a unit that flips between "1024 B" and
// "1.0 KB" or renders "1024.0 PB" is visible jitter in the dashboard.
describe('formatBytes', () => {
  it.each([
    [0, '0 B'],
    [1023, '1023 B'],
    // The boundary: one byte more must roll over to the next unit.
    [1024, '1.0 KB'],
    [1536, '1.5 KB'],
    // One decimal below 10, none at or above it, so the column width stays stable.
    [10 * 1024, '10 KB'],
    [1024 ** 2, '1.0 MB'],
    [1024 ** 3, '1.0 GB'],
    [1024 ** 4, '1.0 TB'],
    [1024 ** 5, '1.0 PB'],
  ])('formats %s as %s', (n, want) => {
    expect(formatBytes(n)).toBe(want)
  })

  // PB is the last unit, so anything larger has to stay in PB rather than run off
  // the end of the table and render undefined.
  it('stops at the largest unit it knows', () => {
    expect(formatBytes(1024 ** 6)).toBe('1024 PB')
  })
})

// "both" runs one rule on each transport. Rendering the bare word leaves the user
// with no way to tell it apart from a TCP-only rule in the forwards table, which is
// exactly where they go to check what a rule actually carries.
describe('ProtocolBadge', () => {
  it.each([
    ['tcp' as const, 'tcp'],
    ['udp' as const, 'udp'],
    ['both' as const, 'tcp + udp'],
  ])('labels %s as %s', (protocol, label) => {
    const { container } = renderScoped(<ProtocolBadge protocol={protocol} />)

    const badge = container.querySelector('.badge')
    expect(badge).toHaveTextContent(label)
    expect(badge).toHaveClass('badge', protocol)
  })
})

// The two directions have opposite blast radius: to_tailnet publishes a local
// service to every device the ACLs allow, to_local only opens a port on this
// machine. Swapping the labels or the tooltips would have someone expose a service
// believing they were reaching one.
describe('DirectionBadge', () => {
  it('says a to_tailnet forward exposes this machine to the tailnet', () => {
    const { container } = renderScoped(<DirectionBadge direction="to_tailnet" />)

    const badge = container.querySelector('.badge')
    expect(badge).toHaveTextContent('to tailnet')
    expect(badge).toHaveAttribute('title', expect.stringContaining('Exposes a local service'))
    expect(badge).toHaveAttribute('title', expect.stringContaining('ACLs'))
  })

  it('says a to_local forward reaches out from this machine', () => {
    const { container } = renderScoped(<DirectionBadge direction="to_local" />)

    const badge = container.querySelector('.badge')
    expect(badge).toHaveTextContent('to local')
    expect(badge).toHaveAttribute('title', expect.stringContaining('Reaches a tailnet service'))
  })
})

describe('StatusDot', () => {
  // The dot is the one thing scanned down the table, so its word has to agree with
  // it: a state conveyed by hue alone is invisible to a colour-blind user.
  it.each([
    ['a running forward', { state: 'running' as const }, 'running', 'running'],
    ['a forward that failed to bind', { state: 'error' as const }, 'error', 'error'],
    ['a forward the tailnet has not reached yet', { state: '' as const }, 'pending', 'waiting'],
    ['a stopped forward', { state: 'stopped' as const }, 'pending', 'waiting'],
  ])('shows %s as %s', (_case, overrides, tone, label) => {
    const { container } = renderScoped(<StatusDot forward={makeForward(overrides)} />)

    const status = container.querySelector('.status')
    expect(status).toHaveTextContent(label)
    expect(status).toHaveClass('status', tone)
  })

  // A rule the user switched off keeps whatever state the engine last reported, and
  // the agent has no reason to overwrite it. Reading state first would leave a
  // switched-off forward showing a green "running" dot.
  it.each([['running' as const], ['error' as const], ['' as const]])(
    'reports a disabled forward as disabled even when its last state was %s',
    (state) => {
      const { container } = renderScoped(
        <StatusDot forward={makeForward({ enabled: false, state })} />,
      )

      const status = container.querySelector('.status')
      expect(status).toHaveTextContent('disabled')
      expect(status).toHaveClass('status', 'off')
    },
  )

  it("hangs the engine's reason off the dot for a forward that failed", () => {
    const { container } = renderScoped(
      <StatusDot forward={makeForward({ state: 'error', error: 'bind: address already in use' })} />,
    )

    expect(container.querySelector('.status')).toHaveAttribute(
      'title',
      'bind: address already in use',
    )
  })
})

// Route puts this machine's side on the left in both directions and points the arrow
// the way traffic travels. Getting either wrong misreads which side is exposed.
describe('Route', () => {
  it('reads left-to-right from this machine out to the tailnet service', () => {
    const { container } = renderScoped(
      <Route
        forward={makeForward({
          direction: 'to_local',
          bindAddr: '127.0.0.1',
          listenPort: 2222,
          target: 'gpu-box.tail1234.ts.net:22',
        })}
      />,
    )

    expect(container.querySelector('.local')).toHaveTextContent('127.0.0.1:2222')
    expect(container.querySelector('.arrow')).toHaveTextContent('→')
    expect(container.querySelector('.remote')).toHaveTextContent('gpu-box.tail1234.ts.net:22')
    expect(container.querySelector('.sr-only')).toHaveTextContent(
      'reaches the tailnet service at gpu-box.tail1234.ts.net:22',
    )
  })

  it('reverses the arrow and names the tailnet port for an exposed service', () => {
    const { container } = renderScoped(
      <Route
        forward={makeForward({
          direction: 'to_tailnet',
          listenPort: 8080,
          target: '127.0.0.1:3000',
        })}
      />,
    )

    expect(container.querySelector('.local')).toHaveTextContent('127.0.0.1:3000')
    expect(container.querySelector('.arrow')).toHaveTextContent('←')
    expect(container.querySelector('.remote')).toHaveTextContent('tailnet:8080')
    expect(container.querySelector('.sr-only')).toHaveTextContent(
      'exposed to the tailnet on port 8080',
    )
  })

  // An empty bindAddr means loopback everywhere else in the stack. Rendering ":2222"
  // reads as "bound to everything", the opposite of what it means.
  it('spells a blank bind address as loopback', () => {
    const { container } = renderScoped(
      <Route forward={makeForward({ direction: 'to_local', bindAddr: '', listenPort: 2222 })} />,
    )

    expect(container.querySelector('.local')).toHaveTextContent('127.0.0.1:2222')
  })

  // The agent reports the address it actually bound, which differs from the
  // configured one whenever a port was auto-suggested. Without this the dashboard
  // shows a port nothing is listening on and the user debugs the wrong number.
  it('exposes the address actually bound on the side that listens', () => {
    const local = renderScoped(
      <Route forward={makeForward({ direction: 'to_local', listening: '127.0.0.1:41002' })} />,
    )
    expect(local.container.querySelector('.local')).toHaveAttribute(
      'title',
      'listening on 127.0.0.1:41002',
    )

    const tailnet = renderScoped(
      <Route forward={makeForward({ direction: 'to_tailnet', listening: '100.64.0.2:8080' })} />,
    )
    expect(tailnet.container.querySelector('.remote')).toHaveAttribute(
      'title',
      'listening on 100.64.0.2:8080',
    )
  })

  it('leaves the hover text off when the agent has not reported a bound address', () => {
    const { container } = renderScoped(<Route forward={makeForward({ direction: 'to_local' })} />)

    expect(container.querySelector('.local')).not.toHaveAttribute('title')
  })
})

// The toggle is the only unlabelled control in the forwards table; without the
// aria-label a screen reader announces a bare checkbox in every row.
describe('Toggle', () => {
  it('reflects its state and reports the value the user switched it to', () => {
    const onChange = vi.fn()
    const { getByLabelText } = renderScoped(
      <Toggle checked={false} onChange={onChange} label="Enable ssh" />,
    )

    const box = getByLabelText('Enable ssh')
    expect(box).not.toBeChecked()

    fireEvent.click(box)

    expect(onChange).toHaveBeenCalledWith(true)
  })

  // user-event rather than fireEvent: a real pointer never reaches a disabled
  // control, and fireEvent dispatches the click regardless, so it would toggle the
  // box in jsdom and prove nothing about what a user can do.
  it('cannot be switched while the row it belongs to is busy', async () => {
    const onChange = vi.fn()
    const { getByLabelText } = renderScoped(
      <Toggle checked onChange={onChange} label="Disable ssh" disabled />,
    )

    const box = getByLabelText('Disable ssh')
    expect(box).toBeChecked()
    expect(box).toBeDisabled()

    await userEvent.setup().click(box)

    expect(onChange).not.toHaveBeenCalled()
    expect(box).toBeChecked()
  })
})

describe('Notice', () => {
  it.each([['error' as const], ['warn' as const], ['info' as const]])(
    'carries its %s tone as a class so the styling can distinguish it',
    (tone) => {
      const { container } = renderScoped(<Notice tone={tone}>something happened</Notice>)

      const notice = container.querySelector('.notice')
      expect(notice).toHaveTextContent('something happened')
      expect(notice).toHaveClass('notice', tone)
    },
  )

  it('defaults to the informational tone', () => {
    const { container } = renderScoped(<Notice>just so you know</Notice>)

    expect(container.querySelector('.notice')).toHaveClass('notice', 'info')
  })
})

// A rate and a total have to agree about what a megabyte is, so this reuses the same
// formatter rather than carrying a second definition of the units.
describe('formatRate', () => {
  it('reads as a byte figure per second', () => {
    expect(formatRate(1024)).toBe('1.0 KB/s')
    expect(formatRate(1024 * 1024 * 2)).toBe('2.0 MB/s')
  })

  // A machine carrying nothing should read as carrying nothing. Rounding a trickle up to
  // "0.4 B/s" makes an idle dashboard look busy.
  it('reads a machine carrying nothing as carrying nothing', () => {
    expect(formatRate(0)).toBe('0 B/s')
    expect(formatRate(0.4)).toBe('0 B/s')
  })

  // A rate is derived by dividing, so a zero-length interval can reach this as Infinity
  // or NaN. Either would render literally on the card.
  it('refuses a figure that is not a number', () => {
    expect(formatRate(Number.NaN)).toBe('0 B/s')
    expect(formatRate(Number.POSITIVE_INFINITY)).toBe('0 B/s')
  })
})
