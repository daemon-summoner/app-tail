// SPDX-License-Identifier: MIT

import { fireEvent, within } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'

import { deferred, emptySettingsForm, failWith, makeForward, makeTunnel, noContent, renderAgent, settle, stubConfirm } from '../test/agent'
import { ForwardsTable } from './ForwardsTable'

/** table mounts the panel with the props App always supplies, so a test only has to
 *  say what is different about its case. */
function table(
  props: Partial<Parameters<typeof ForwardsTable>[0]> = {},
): Parameters<typeof ForwardsTable>[0] {
  return {
    forwards: [],
    // One connection is what every install has, and it is what makes the connection
    // column absent by default: a column repeating one word on every row is noise.
    tunnels: [makeTunnel()],
    nodeRunning: true,
    onChanged: () => {},
    onEdit: () => {},
    onAdd: () => {},
    form: emptySettingsForm(),
    ...props,
  }
}

/** rowFor finds a forward's row by the name shown in it. */
function rowFor(container: HTMLElement, name: string): HTMLElement {
  const row = within(container)
    .getAllByRole('row')
    .find((r) => within(r).queryByText(name) !== null)
  if (row === undefined) throw new Error(`no row named ${name}`)
  return row
}

describe('the empty table', () => {
  // A first-run dashboard with a bare "Forwards" heading and nothing under it gives
  // no clue what a forward even is, which is the whole first-use problem.
  it('explains what a forward is and offers to create one', async () => {
    const onAdd = vi.fn()
    const { getByText, getByRole } = await renderAgent(<ForwardsTable {...table({ onAdd })} form={emptySettingsForm()} />)

    expect(getByText('No forwards yet')).toBeInTheDocument()
    fireEvent.click(getByRole('button', { name: 'Add your first forward' }))

    expect(onAdd).toHaveBeenCalledTimes(1)
  })

  it('shows no table at all rather than an empty one', async () => {
    const { queryByRole } = await renderAgent(<ForwardsTable {...table()} form={emptySettingsForm()} />)

    expect(queryByRole('table')).not.toBeInTheDocument()
  })
})

// A both-protocol forward carries TCP connections and UDP sessions at the same
// time. Reading only one counter under-reports live traffic, and someone deciding
// whether a rule is safe to delete would see 0 while sessions are still open.
describe('the live connection count', () => {
  it.each([
    ['tcp' as const, 3, 7, '3'],
    ['udp' as const, 3, 7, '7'],
    ['both' as const, 3, 7, '10'],
  ])('a %s forward with %s tcp and %s udp shows %s', async (protocol, activeTcp, activeUdp, want) => {
    const { container } = await renderAgent(
      <ForwardsTable
        {...table({ forwards: [makeForward({ name: 'svc', protocol, activeTcp, activeUdp })] })} form={emptySettingsForm()} />,
    )

    // Numeric columns in order: connections, bytes up, bytes down.
    expect(rowFor(container, 'svc').querySelectorAll('.numeric')[0]).toHaveTextContent(want)
  })
})

describe('deleting a forward', () => {
  // A forward is cheap to recreate but its loss is silent -- open connections drop
  // and nothing records that it ever existed.
  it('does nothing at all when the confirmation is declined', async () => {
    const confirm = stubConfirm(false)
    const onChanged = vi.fn()
    const { container, agent } = await renderAgent(
      <ForwardsTable {...table({ forwards: [makeForward({ name: 'ssh' })], onChanged })} form={emptySettingsForm()} />,
    )

    fireEvent.click(within(rowFor(container, 'ssh')).getByRole('button', { name: 'Delete' }))
    await settle()

    expect(confirm).toHaveBeenCalledTimes(1)
    expect(agent.countOf('DELETE /api/forwards')).toBe(0)
    expect(onChanged).not.toHaveBeenCalled()
  })

  // The prompt has to name the forward: two rules on neighbouring rows look alike,
  // and an unnamed one is only identifiable by its endpoint.
  it.each([
    ['a named forward', { name: 'ssh' }, 'ssh'],
    ['an unnamed forward', { name: '', endpoint: 'tcp 127.0.0.1:2222' }, 'tcp 127.0.0.1:2222'],
  ])('names %s in the prompt', async (_case, overrides, label) => {
    const confirm = stubConfirm(false)
    const { container } = await renderAgent(
      <ForwardsTable {...table({ forwards: [makeForward(overrides)] })} form={emptySettingsForm()} />,
    )

    const row = within(container).getAllByRole('row')[1]!
    fireEvent.click(within(row).getByRole('button', { name: 'Delete' }))

    expect(confirm).toHaveBeenCalledWith(expect.stringContaining(`"${label}"`))
  })

  it('deletes and asks the dashboard to refresh once confirmed', async () => {
    stubConfirm(true)
    const onChanged = vi.fn()
    const { container, agent } = await renderAgent(
      <ForwardsTable {...table({ forwards: [makeForward({ id: 'fwd-ssh', name: 'ssh' })], onChanged })} form={emptySettingsForm()} />,
      { 'DELETE /api/forwards': noContent() },
    )

    fireEvent.click(within(rowFor(container, 'ssh')).getByRole('button', { name: 'Delete' }))
    await settle()

    expect(agent.urlOf('DELETE /api/forwards')).toBe('/api/forwards/fwd-ssh')
    expect(onChanged).toHaveBeenCalledTimes(1)
  })

  // A refused delete has to say why. Without this the row simply stays put and the
  // user clicks Delete again, forever.
  it('shows the reason the agent refused and leaves the row alone', async () => {
    stubConfirm(true)
    const onChanged = vi.fn()
    const { container, getByText } = await renderAgent(
      <ForwardsTable {...table({ forwards: [makeForward({ name: 'ssh' })], onChanged })} form={emptySettingsForm()} />,
      { 'DELETE /api/forwards': failWith(409, 'the forward is still shutting down') },
    )

    fireEvent.click(within(rowFor(container, 'ssh')).getByRole('button', { name: 'Delete' }))
    await settle()

    expect(getByText('the forward is still shutting down')).toBeInTheDocument()
    expect(onChanged).not.toHaveBeenCalled()
  })
})

describe('toggling a forward', () => {
  it('posts the new state and refreshes', async () => {
    const onChanged = vi.fn()
    const { container, agent } = await renderAgent(
      <ForwardsTable
        {...table({ forwards: [makeForward({ id: 'fwd-ssh', name: 'ssh', enabled: true })], onChanged })} form={emptySettingsForm()} />,
      { 'POST /api/forwards/fwd-ssh/toggle': makeForward({ enabled: false }) },
    )

    fireEvent.click(within(rowFor(container, 'ssh')).getByLabelText('Disable ssh'))
    await settle()

    expect(agent.bodyOf('POST /api/forwards/fwd-ssh/toggle')).toEqual({ enabled: false })
    expect(onChanged).toHaveBeenCalledTimes(1)
  })

  // busyId is one value for the whole table. Guarding on truthiness rather than
  // matching the id would freeze every row while any single one is in flight, and a
  // slow agent would lock the dashboard on every click.
  it('disables only the row that is waiting on the agent', async () => {
    const pending = deferred<void>()
    const { container } = await renderAgent(
      <ForwardsTable
        {...table({
          forwards: [
            makeForward({ id: 'fwd-a', name: 'alpha' }),
            makeForward({ id: 'fwd-b', name: 'bravo' }),
          ],
        })} form={emptySettingsForm()} />,
      {
        'POST /api/forwards/fwd-a/toggle': () => pending.promise.then(() => makeForward()),
      },
    )

    const alpha = rowFor(container, 'alpha')
    const bravo = rowFor(container, 'bravo')
    fireEvent.click(within(alpha).getByLabelText('Disable alpha'))
    await settle(1)

    expect(within(alpha).getByLabelText('Disable alpha')).toBeDisabled()
    expect(within(alpha).getByRole('button', { name: 'Delete' })).toBeDisabled()
    expect(within(bravo).getByLabelText('Disable bravo')).toBeEnabled()
    expect(within(bravo).getByRole('button', { name: 'Delete' })).toBeEnabled()

    pending.resolve()
    await settle()

    expect(within(alpha).getByLabelText('Disable alpha')).toBeEnabled()
  })
})

// A module rebuilds its forwards from the tailnet on every reconcile, and the agent
// refuses a write to what it derived. Offering a control that is then refused is
// precisely what the source field exists to prevent, so the row carries none of those.
describe('a forward a module created', () => {
  const automatic = () =>
    makeForward({ id: 'auto_peer1_22', name: 'gpu-box:22', source: 'auto' as const })

  it('offers no way to edit or delete it', async () => {
    const { container } = await renderAgent(
      <ForwardsTable {...table({ forwards: [automatic()] })} form={emptySettingsForm()} />,
    )

    const row = within(rowFor(container, 'gpu-box:22'))
    expect(row.queryByRole('button', { name: 'Edit' })).toBeNull()
    expect(row.queryByRole('button', { name: 'Delete' })).toBeNull()
  })

  // The switch is the one control the agent accepts, and without it the only way to
  // close one port is to turn the module off and lose every other mapping with it.
  it('can still be switched off on its own', async () => {
    const onChanged = vi.fn()
    const { container, agent } = await renderAgent(
      <ForwardsTable {...table({ forwards: [automatic()], onChanged })} form={emptySettingsForm()} />,
      { 'POST /api/forwards/auto_peer1_22/toggle': makeForward({ enabled: false }) },
    )

    fireEvent.click(within(rowFor(container, 'gpu-box:22')).getByLabelText('Disable gpu-box:22'))
    await settle()

    expect(agent.bodyOf('POST /api/forwards/auto_peer1_22/toggle')).toEqual({ enabled: false })
    expect(onChanged).toHaveBeenCalledTimes(1)
  })

  it('says why, rather than leaving an unexplained gap where the controls were', async () => {
    const { container } = await renderAgent(
      <ForwardsTable {...table({ forwards: [automatic()] })} form={emptySettingsForm()} />,
    )

    expect(rowFor(container, 'gpu-box:22')).toHaveTextContent('automatic')
  })

  // The controls are hidden per row, not per table: a user-created forward alongside a
  // derived one must still be editable.
  it('leaves the controls on the rows a user created', async () => {
    const { container } = await renderAgent(
      <ForwardsTable {...table({ forwards: [automatic(), makeForward({ name: 'ssh' })] })} form={emptySettingsForm()} />,
    )

    const row = within(rowFor(container, 'ssh'))
    expect(row.getByRole('button', { name: 'Edit' })).toBeInTheDocument()
    expect(row.getByRole('button', { name: 'Delete' })).toBeInTheDocument()
  })
})

describe('what each row tells the user', () => {
  // A forward can be enabled and correct while the node is still connecting. Without
  // the hint its "waiting" dot reads as a broken rule and sends the user to debug
  // the forward instead of the tailnet.
  it('blames the tailnet, not the rule, while the node is down', async () => {
    const { container } = await renderAgent(
      <ForwardsTable
        {...table({
          nodeRunning: false,
          forwards: [makeForward({ name: 'ssh', enabled: true, state: '' })],
        })} form={emptySettingsForm()} />,
    )

    expect(rowFor(container, 'ssh')).toHaveTextContent('waiting for the tailnet')
  })

  it.each([
    ['the node is up', true, { enabled: true, state: '' as const }],
    ['the forward is already running', false, { enabled: true, state: 'running' as const }],
    ['the forward is switched off', false, { enabled: false, state: '' as const }],
  ])('leaves the hint off when %s', async (_case, nodeRunning, overrides) => {
    const { container } = await renderAgent(
      <ForwardsTable {...table({ nodeRunning, forwards: [makeForward({ name: 'ssh', ...overrides })] })} form={emptySettingsForm()} />,
    )

    expect(rowFor(container, 'ssh')).not.toHaveTextContent('waiting for the tailnet')
  })

  // With one network every row would name the same one, which is a column of noise. The
  // question only exists once a forward could be on a network other than the obvious one.
  it('names no connection while there is only one to be on', async () => {
    const { queryByText, container } = await renderAgent(
      <ForwardsTable {...table({ forwards: [makeForward({ name: 'ssh' })] })} form={emptySettingsForm()} />,
    )

    expect(queryByText('Connection')).not.toBeInTheDocument()
    expect(rowFor(container, 'ssh')).not.toHaveTextContent('Tailnet')
  })

  // Two networks can hold the same address and the same device name, so which one a rule
  // crosses is the thing that tells two otherwise identical rows apart.
  it('names the connection each forward crosses once there is more than one', async () => {
    const { container, getByText } = await renderAgent(
      <ForwardsTable
        {...table({
          tunnels: [makeTunnel(), makeTunnel({ id: 'tn_office', name: 'Office', slug: 'office' })],
          forwards: [
            makeForward({ id: 'fwd-home', name: 'nas' }),
            makeForward({ id: 'fwd-office', name: 'db', tunnelId: 'tn_office' }),
          ],
        })} form={emptySettingsForm()} />,
    )

    expect(getByText('Connection')).toBeInTheDocument()
    expect(rowFor(container, 'nas')).toHaveTextContent('Tailnet')
    expect(rowFor(container, 'db')).toHaveTextContent('Office')
  })

  // The name is optional, and a blank cell leaves a row with no handle at all.
  it('calls a nameless forward Unnamed', async () => {
    const { getByText } = await renderAgent(
      <ForwardsTable {...table({ forwards: [makeForward({ name: '' })] })} form={emptySettingsForm()} />,
    )

    expect(getByText('Unnamed')).toBeInTheDocument()
  })

  it("surfaces the engine's error next to the route it belongs to", async () => {
    const { container } = await renderAgent(
      <ForwardsTable
        {...table({
          forwards: [makeForward({ name: 'ssh', state: 'error', error: 'bind: address already in use' })],
        })} form={emptySettingsForm()} />,
    )

    expect(rowFor(container, 'ssh')).toHaveTextContent('bind: address already in use')
  })

  // A forward listening beyond this machine is running exactly as configured, so nothing
  // else on the row can show it: same dot, same route, same counts as a loopback one. The
  // agent writes the sentence and this row is the only place it is read.
  it('shows what is true about a forward that its state cannot show', async () => {
    const warning =
      'This forward listens on every address this machine has, so anything that can reach ' +
      'this machine over the networks it is on can use it, not only programs running here.'
    const { container } = await renderAgent(
      <ForwardsTable
        {...table({ forwards: [makeForward({ name: 'ssh', warning })] })} form={emptySettingsForm()} />,
    )

    expect(rowFor(container, 'ssh')).toHaveTextContent('listens on every address this machine has')
  })

  it('says nothing extra about a forward with nothing to warn about', async () => {
    const { container } = await renderAgent(
      <ForwardsTable {...table({ forwards: [makeForward({ name: 'ssh' })] })} form={emptySettingsForm()} />,
    )

    expect(rowFor(container, 'ssh').querySelector('.forward-warning')).toBeNull()
  })

  it('marks a disabled row so it reads as switched off rather than broken', async () => {
    const { container } = await renderAgent(
      <ForwardsTable {...table({ forwards: [makeForward({ name: 'ssh', enabled: false })] })} form={emptySettingsForm()} />,
    )

    expect(rowFor(container, 'ssh')).toHaveClass('disabled')
  })

  // Without scope="col" a screen reader reading down the table announces the cells
  // with no idea which column each belongs to.
  it('scopes its column headers', async () => {
    const { getAllByRole } = await renderAgent(
      <ForwardsTable {...table({ forwards: [makeForward()] })} form={emptySettingsForm()} />,
    )

    const headers = getAllByRole('columnheader')
    expect(headers).toHaveLength(8)
    for (const header of headers) {
      expect(header).toHaveAttribute('scope', 'col')
    }
  })

  it('hands the whole forward back when a row is opened for editing', async () => {
    const onEdit = vi.fn()
    const forward = makeForward({ id: 'fwd-ssh', name: 'ssh' })
    const { container } = await renderAgent(
      <ForwardsTable {...table({ forwards: [forward], onEdit })} form={emptySettingsForm()} />,
    )

    fireEvent.click(within(rowFor(container, 'ssh')).getByRole('button', { name: 'Edit' }))

    expect(onEdit).toHaveBeenCalledWith(forward)
  })
})
