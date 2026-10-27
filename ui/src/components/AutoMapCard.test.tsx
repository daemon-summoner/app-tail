// SPDX-License-Identifier: MIT

import { fireEvent } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'

import { deferred, emptySettingsForm, failWith, makeAutoMap, renderAgent, settle } from '../test/agent'
import { AutoMapCard } from './AutoMapCard'
import type { AutoMapView } from '../api'

function card(view: AutoMapView, onChanged = vi.fn()) {
  return <AutoMapCard view={view} onChanged={onChanged} form={emptySettingsForm()} />
}

// The port list is the entire configuration of the module, so it is stated rather than
// counted: "3 ports" does not tell anyone whether the one they wanted is among them.
it('names the ports it opens on every device', async () => {
  const { getByText } = await renderAgent(card(makeAutoMap({ enabled: true, ports: [22, 80] })))

  expect(getByText(/Port 22, 80 on every device/)).toBeInTheDocument()
})

// Assignments outlive the devices that hold them on purpose -- that is what keeps a
// bookmarked port stable. So the count of remembered ones has to be separate from the
// count currently open, or nothing on screen explains why forgetting would do anything.
it('separates the ports open now from the ones remembered', async () => {
  const { container } = await renderAgent(
    card(makeAutoMap({ enabled: true, mapped: 3, stored: 11 })),
  )

  const counters = [...container.querySelectorAll('.proxy-counters div')].map(
    (row) => row.textContent,
  )
  expect(counters).toEqual(['Open now3', 'Remembered11'])
})

describe('forgetting devices that are gone', () => {
  // Renumbering a device breaks every bookmark that named its old port, so this is a
  // deliberate action. With nothing remembered there is nothing it could do.
  it('is not offered when nothing is remembered', async () => {
    const { getByRole } = await renderAgent(card(makeAutoMap({ enabled: true, stored: 0 })))

    expect(getByRole('button', { name: 'Forget devices that are gone' })).toBeDisabled()
  })

  it('asks the agent and reports how many it dropped', async () => {
    const onChanged = vi.fn()
    const { agent, getByRole, getByText } = await renderAgent(
      card(makeAutoMap({ enabled: true, stored: 4 }), onChanged),
      {
        'POST /api/automap/forget': { removed: 2, automap: makeAutoMap({ enabled: true, stored: 2 }) },
      },
    )

    fireEvent.click(getByRole('button', { name: 'Forget devices that are gone' }))
    await settle()

    expect(agent.countOf('POST /api/automap/forget')).toBe(1)
    expect(getByText('Forgot 2 port assignments.')).toBeInTheDocument()
    // The forwards the module owns disappear with the assignment, so the panels that
    // render them have to be told; a count that only changed on the next poll would
    // read as the button having done nothing.
    expect(onChanged).toHaveBeenCalled()
  })

  it('says so plainly when every remembered device is still here', async () => {
    const { getByRole, getByText } = await renderAgent(
      card(makeAutoMap({ enabled: true, stored: 4 })),
      { 'POST /api/automap/forget': { removed: 0, automap: makeAutoMap({ enabled: true, stored: 4 }) } },
    )

    fireEvent.click(getByRole('button', { name: 'Forget devices that are gone' }))
    await settle()

    expect(
      getByText('Every remembered port belongs to a device still on the tailnet.'),
    ).toBeInTheDocument()
  })

  // A refusal that vanished would leave the user believing ports were dropped when
  // they were not, and the counts on screen would agree with that belief.
  it('shows the agent’s refusal instead of reporting success', async () => {
    const onChanged = vi.fn()
    const { getByRole, getByText } = await renderAgent(
      card(makeAutoMap({ enabled: true, stored: 4 }), onChanged),
      { 'POST /api/automap/forget': failWith(503, 'the tailnet node is not running') },
    )

    fireEvent.click(getByRole('button', { name: 'Forget devices that are gone' }))
    await settle()

    expect(getByText('the tailnet node is not running')).toBeInTheDocument()
    expect(onChanged).not.toHaveBeenCalled()
  })

  it('cannot be pressed twice while the first request is still open', async () => {
    const pending = deferred<{ removed: number; automap: AutoMapView }>()
    const { agent, getByRole } = await renderAgent(card(makeAutoMap({ enabled: true, stored: 4 })), {
      'POST /api/automap/forget': () => pending.promise,
    })

    const button = getByRole('button', { name: 'Forget devices that are gone' })
    fireEvent.click(button)
    await settle(1)
    expect(button).toBeDisabled()

    pending.resolve({ removed: 1, automap: makeAutoMap({ enabled: true, stored: 3 }) })
    await settle()
    expect(agent.countOf('POST /api/automap/forget')).toBe(1)
  })
})

// An empty port list is a working configuration that opens nothing, so the card has to
// say that. Rendering "Port  on every device is opened" would read as a display bug and
// send the user looking for ports the module was never asked to open.
it('says it opens nothing when no port is configured', async () => {
  const { getByText } = await renderAgent(card(makeAutoMap({ enabled: true, ports: [] })))

  expect(getByText('No ports are configured, so nothing is opened.')).toBeInTheDocument()
})

// The limit is a real cap with a real consequence, so what it left out is reported.
// Silently mapping the first 32 devices is how "my laptop is missing" becomes a bug
// report about the tailnet rather than about the limit.
it('reports the devices the limit left out rather than hiding them', async () => {
  const { getByText } = await renderAgent(
    card(
      makeAutoMap({
        enabled: true,
        limit: 32,
        mapped: 32,
        truncated: 9,
        reason: '9 device-and-port pairs were left out; raise the limit to open them.',
      }),
    ),
  )

  expect(
    getByText('9 device-and-port pairs were left out; raise the limit to open them.'),
  ).toBeInTheDocument()
})

// The count is what the agent always reports; the sentence is what it sometimes adds. A
// truncation the agent could not explain still has to say something, or the one state the
// user needs to act on is the one that renders as nothing.
it('states the truncation itself when the agent explained nothing', async () => {
  const { getByText } = await renderAgent(
    card(makeAutoMap({ enabled: true, limit: 32, mapped: 32, truncated: 9 })),
  )

  expect(
    getByText('9 more device-and-port pairs were left out by the limit of 32.'),
  ).toBeInTheDocument()
})

// The agent explains why it opened fewer ports than asked for reasons other than the
// limit -- a device with no address yet, a port already claimed. Nothing was truncated,
// so the warning tone would be wrong, but staying silent leaves the counts unexplained.
it('passes on an explanation that is not about the limit as information', async () => {
  const { getByText } = await renderAgent(
    card(
      makeAutoMap({
        enabled: true,
        mapped: 2,
        reason: 'One device has no tailnet address yet, so no port was opened for it.',
      }),
    ),
  )

  const notice = getByText('One device has no tailnet address yet, so no port was opened for it.')
  expect(notice).toBeInTheDocument()
  expect(notice.className).toContain('info')
})
