// SPDX-License-Identifier: MIT

import { fireEvent, within } from '@testing-library/react'
import { describe, expect, it } from 'vitest'

import {
  deferred,
  failWith,
  makePreset,
  netFail,
  noContent,
  renderAgent,
  settle,
} from '../test/agent'
import type { AgentView, Routes } from '../test/agent'
import { PresetManager } from './PresetManager'
import type { Preset } from '../api'

async function open(routes: Routes = {}): Promise<AgentView> {
  return renderAgent(<PresetManager />, routes)
}

/** newPreset fills the add form. */
function newPreset(view: AgentView, name: string, port: string, protocol?: string): void {
  fireEvent.change(view.getByLabelText('Name'), { target: { value: name } })
  fireEvent.change(view.getByLabelText('Port'), { target: { value: port } })
  if (protocol !== undefined) {
    fireEvent.change(view.getByLabelText('Protocol'), { target: { value: protocol } })
  }
}

function addButton(view: AgentView): HTMLElement {
  return view.getByRole('button', { name: 'Add' })
}

// A preset with no name is unpickable in the forward dialog, and one with a port
// outside 1-65535 produces a forward the agent refuses. Both are only catchable
// here: the add form is the single place either can be entered.
describe('when Add becomes available', () => {
  it.each([
    ['nothing typed', '', ''],
    ['a name but no port', 'Postgres', ''],
    ['a port but no name', '', '5432'],
    ['a name that is only spaces', '   ', '5432'],
    ['a port of zero', 'Postgres', '0'],
    ['a port above the maximum', 'Postgres', '65536'],
    ['a fractional port', 'Postgres', '54.32'],
  ])('stays disabled with %s', async (_case, name, port) => {
    const view = await open()

    newPreset(view, name, port)

    expect(addButton(view)).toBeDisabled()
  })

  it.each([
    ['the lowest port', 'Postgres', '1'],
    ['the highest port', 'Postgres', '65535'],
    ['an ordinary port', 'Postgres', '5432'],
  ])('enables with a name and %s', async (_case, name, port) => {
    const view = await open()

    newPreset(view, name, port)

    expect(addButton(view)).toBeEnabled()
  })
})

describe('adding a preset', () => {
  it('sends the trimmed name with the chosen protocol and port', async () => {
    const view = await open({ 'POST /api/presets': makePreset() })

    newPreset(view, '  Postgres  ', '5432', 'both')
    fireEvent.click(addButton(view))
    await settle()

    expect(view.agent.bodyOf('POST /api/presets')).toEqual({
      name: 'Postgres',
      protocol: 'both',
      remotePort: 5432,
    })
  })

  // Adding several presets in a row is the normal case. Leaving the previous entry
  // in the fields makes the next add silently a duplicate of the last one.
  it('clears the whole form after a successful add', async () => {
    const view = await open({ 'POST /api/presets': makePreset() })

    newPreset(view, 'Postgres', '5432', 'udp')
    fireEvent.click(addButton(view))
    await settle()

    expect(view.getByLabelText('Name')).toHaveValue('')
    expect(view.getByLabelText('Port')).toHaveValue(null)
    // The protocol resets too: a leftover "udp" would silently mislabel the next
    // preset the user adds without looking.
    expect(view.getByLabelText('Protocol')).toHaveValue('tcp')
  })

  // Discarding the input on a rejection makes the user retype everything to fix one
  // character of it.
  it('keeps what was typed when the agent rejects it', async () => {
    const view = await open({
      'POST /api/presets': failWith(409, 'a preset named Postgres already exists'),
    })

    newPreset(view, 'Postgres', '5432')
    fireEvent.click(addButton(view))
    await settle()

    expect(view.getByText('a preset named Postgres already exists')).toBeInTheDocument()
    expect(view.getByLabelText('Name')).toHaveValue('Postgres')
    expect(view.getByLabelText('Port')).toHaveValue(5432)
  })

  // The list is re-read rather than patched locally, so the id the agent minted is
  // the one the delete button will later use.
  it('re-reads the catalog so the new preset carries its real id', async () => {
    let listed = 0
    const view = await open({
      'GET /api/presets': () => {
        listed += 1
        return { presets: listed === 1 ? [] : [makePreset({ id: 'preset-1', name: 'Postgres' })] }
      },
      'POST /api/presets': makePreset({ id: 'preset-1', name: 'Postgres' }),
    })

    newPreset(view, 'Postgres', '5432')
    fireEvent.click(addButton(view))
    await settle()

    expect(view.agent.countOf('GET /api/presets')).toBe(2)
    expect(view.getByText('Postgres')).toBeInTheDocument()
  })

  it('cannot be pressed twice while the agent is writing', async () => {
    const pending = deferred<Preset>()
    const view = await open({ 'POST /api/presets': () => pending.promise })

    newPreset(view, 'Postgres', '5432')
    fireEvent.click(addButton(view))
    await settle(1)

    expect(addButton(view)).toBeDisabled()

    pending.resolve(makePreset())
    await settle()

    expect(view.agent.countOf('POST /api/presets')).toBe(1)
  })
})

describe('the catalog it lists', () => {
  // Built-ins belong to the binary: a Delete button on one either fails or removes
  // an entry the next release puts straight back.
  it('offers no delete on a built-in preset', async () => {
    const view = await open({
      'GET /api/presets': {
        presets: [
          makePreset({ id: 'p-ssh', name: 'SSH', builtIn: true }),
          makePreset({ id: 'p-pg', name: 'Postgres', remotePort: 5432, builtIn: false }),
        ],
      },
    })

    const items = view.container.querySelectorAll('.picker-item')
    expect(within(items[0] as HTMLElement).queryByRole('button', { name: 'Delete' })).toBeNull()
    expect(within(items[0] as HTMLElement).getByText('built-in')).toBeInTheDocument()
    expect(
      within(items[1] as HTMLElement).getByRole('button', { name: 'Delete' }),
    ).toBeInTheDocument()
  })

  it('deletes a user preset and re-reads the catalog', async () => {
    const view = await open({
      'GET /api/presets': { presets: [makePreset({ id: 'p-pg', name: 'Postgres', builtIn: false })] },
      'DELETE /api/presets': noContent(),
    })

    fireEvent.click(view.getByRole('button', { name: 'Delete' }))
    await settle()

    expect(view.agent.urlOf('DELETE /api/presets')).toBe('/api/presets/p-pg')
    expect(view.agent.countOf('GET /api/presets')).toBe(2)
  })

  it('reports a delete the agent refused', async () => {
    const view = await open({
      'GET /api/presets': { presets: [makePreset({ id: 'p-pg', builtIn: false })] },
      'DELETE /api/presets': failWith(403, 'built-in presets cannot be removed'),
    })

    fireEvent.click(view.getByRole('button', { name: 'Delete' }))
    await settle()

    expect(view.getByText('built-in presets cannot be removed')).toBeInTheDocument()
  })

  it.each([
    ['tcp' as const, 'TCP 22'],
    ['udp' as const, 'UDP 53'],
    ['both' as const, 'tcp + udp 53'],
  ])('describes a %s preset as %s', async (protocol, want) => {
    const view = await open({
      'GET /api/presets': {
        presets: [makePreset({ protocol, remotePort: protocol === 'tcp' ? 22 : 53 })],
      },
    })

    expect(view.container.querySelector('.picker-item')).toHaveTextContent(want)
  })

  // An empty list and a list that has not arrived look identical otherwise, and a
  // user who sees no presets assumes there are none rather than waiting.
  it('says it is loading before the catalog arrives', async () => {
    const pending = deferred<{ presets: Preset[] }>()
    const view = await open({ 'GET /api/presets': () => pending.promise })

    expect(view.getByText('Loading presets…')).toBeInTheDocument()

    pending.resolve({ presets: [] })
    await settle()

    expect(view.queryByText('Loading presets…')).not.toBeInTheDocument()
  })

  it('explains a catalog it could not read', async () => {
    const view = await open({ 'GET /api/presets': netFail() })

    expect(view.getByText(/cannot reach the app-tail agent/)).toBeInTheDocument()
  })
})

// Presets are defaults for the add-forward dialog: set once, then not looked at again.
// Open by default they push the forwards themselves -- the card's actual subject -- down
// the page for a table nobody came to read.
describe('how much room the presets take', () => {
  it('starts shut', async () => {
    const { container } = await open()

    const details = container.querySelector('details.advanced')
    expect(details).toBeInTheDocument()
    expect((details as HTMLDetailsElement).open).toBe(false)
  })

  it('opens to the presets on request', async () => {
    const view = await open({ 'GET /api/presets': { presets: [makePreset({ name: 'SSH' })] } })

    fireEvent.click(view.getByText('Service presets'))
    await settle()

    const details = view.container.querySelector('details.advanced') as HTMLDetailsElement
    expect(details.open).toBe(true)
    expect(within(details).getByText('SSH')).toBeInTheDocument()
  })
})
