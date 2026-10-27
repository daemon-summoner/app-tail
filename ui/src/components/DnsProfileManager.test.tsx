// SPDX-License-Identifier: MIT

import { fireEvent } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'

import {
  builtInDNSProfiles,
  failWith,
  makeDNSProfile,
  noContent,
  pressEscape,
  renderAgent,
  reply,
  settle,
} from '../test/agent'
import { DnsProfileManager } from './DnsProfileManager'

/** The catalog as it stands after somebody has added one of their own. */
function catalog() {
  return [...builtInDNSProfiles(), makeDNSProfile()]
}

// The shipped profiles are the way back when a custom one is what broke resolution, so
// nothing in this list may offer to remove them.
it('offers no way to edit or delete a built-in profile', async () => {
  const { queryByLabelText, getByLabelText } = await renderAgent(
    <DnsProfileManager profiles={catalog()} onChanged={() => {}} />,
  )

  expect(queryByLabelText('Delete Cloudflare')).not.toBeInTheDocument()
  expect(queryByLabelText('Edit Google')).not.toBeInTheDocument()
  expect(getByLabelText('Delete NextDNS')).toBeInTheDocument()
})

// "Delete" three times over says nothing about which row a button belongs to, which is the
// difference between deleting the profile you meant and the one above it.
it('names the profile each button acts on', async () => {
  const { getByLabelText } = await renderAgent(
    <DnsProfileManager profiles={catalog()} onChanged={() => {}} />,
  )

  expect(getByLabelText('Edit NextDNS')).toBeInTheDocument()
  expect(getByLabelText('Delete NextDNS')).toBeInTheDocument()
})

it('removes a profile and tells the card to re-read the catalog', async () => {
  const changed = vi.fn()
  const { getByLabelText, agent } = await renderAgent(
    <DnsProfileManager profiles={catalog()} onChanged={changed} />,
    { 'DELETE /api/dns/profiles': noContent() },
  )

  fireEvent.click(getByLabelText('Delete NextDNS'))
  await settle()

  expect(agent.urlOf('DELETE /api/dns/profiles')).toBe('/api/dns/profiles/nextdns')
  expect(changed).toHaveBeenCalled()
})

// Deleting the profile the machine is using is refused by the agent until the machine is
// put back. A refusal that vanished would read as a delete that worked.
it('states a refused delete rather than swallowing it', async () => {
  const { getByLabelText, getByText } = await renderAgent(
    <DnsProfileManager profiles={catalog()} onChanged={() => {}} />,
    { 'DELETE /api/dns/profiles': failWith(400, 'this machine is still pointed at NextDNS') },
  )

  fireEvent.click(getByLabelText('Delete NextDNS'))
  await settle()

  expect(getByText(/still pointed at NextDNS/)).toBeInTheDocument()
})

describe('the profile dialog', () => {
  const openDialog = async (label = 'Add a profile') => {
    const view = await renderAgent(<DnsProfileManager profiles={catalog()} onChanged={() => {}} />, {
      'POST /api/dns/profiles': reply(201, makeDNSProfile({ id: 'work', name: 'Work' })),
      'PUT /api/dns/profiles': reply(200, makeDNSProfile({ name: 'NextDNS' })),
    })
    fireEvent.click(view.getByRole('button', { name: label }))
    await settle()
    return view
  }

  it('refuses to save a profile with no name or no server', async () => {
    const { getByRole, getByLabelText } = await openDialog()

    expect(getByRole('button', { name: 'Add profile' })).toBeDisabled()

    fireEvent.change(getByLabelText('Name'), { target: { value: 'Work' } })
    expect(getByRole('button', { name: 'Add profile' })).toBeDisabled()

    fireEvent.change(getByLabelText('Server'), { target: { value: '10.0.0.1' } })
    expect(getByRole('button', { name: 'Add profile' })).toBeEnabled()
  })

  // The order is the failover order -- app-tail stays on the first server that answers --
  // so a form that reordered or dropped the blanks unevenly would change which resolver
  // actually answers.
  it('sends the servers in the order they were typed, blanks left out', async () => {
    const { getByRole, getByLabelText, agent } = await openDialog()

    fireEvent.change(getByLabelText('Name'), { target: { value: 'Work' } })
    fireEvent.change(getByLabelText('Server'), { target: { value: 'tls://dot.example.com' } })
    fireEvent.click(getByRole('button', { name: 'Add another server' }))
    fireEvent.change(getByLabelText('Backup server 1'), { target: { value: '10.0.0.2' } })
    fireEvent.click(getByRole('button', { name: 'Add profile' }))
    await settle()

    expect(agent.bodyOf('POST /api/dns/profiles')).toEqual({
      name: 'Work',
      servers: ['tls://dot.example.com', '10.0.0.2'],
    })
  })

  // The id has to survive an edit: the settings point at it, so a save that minted a new
  // one would leave the machine resolving through a profile nothing selects any more.
  it('edits in place, keeping the id the settings point at', async () => {
    const { getByRole, getByLabelText, agent } = await openDialog('Edit NextDNS')

    fireEvent.change(getByLabelText('Server'), { target: { value: 'https://dns.nextdns.io/xyz' } })
    fireEvent.click(getByRole('button', { name: 'Save changes' }))
    await settle()

    expect(agent.urlOf('PUT /api/dns/profiles')).toBe('/api/dns/profiles/nextdns')
    expect(agent.bodyOf('PUT /api/dns/profiles')).toEqual({
      name: 'NextDNS',
      servers: ['https://dns.nextdns.io/xyz'],
    })
  })

  // The agent hides the part of a DoH URL that identifies the account, because its answer
  // goes to every process on this machine. The form has to hand that stand-in back
  // exactly as it was shown -- the agent restores the real URL from it -- and to say why a
  // box reads like that, or the next thing somebody does is type over it from memory.
  it('explains a hidden server and sends it back untouched', async () => {
    const hidden = makeDNSProfile({ servers: ['https://dns.nextdns.io/...'] })
    const view = await renderAgent(
      <DnsProfileManager profiles={[...builtInDNSProfiles(), hidden]} onChanged={() => {}} />,
      { 'PUT /api/dns/profiles': reply(200, hidden) },
    )
    fireEvent.click(view.getByLabelText('Edit NextDNS'))
    await settle()

    expect(view.getByText(/hides the part of its address/)).toBeInTheDocument()

    fireEvent.change(view.getByLabelText('Name'), { target: { value: 'Work DNS' } })
    fireEvent.click(view.getByRole('button', { name: 'Save changes' }))
    await settle()

    expect(view.agent.bodyOf('PUT /api/dns/profiles')).toEqual({
      name: 'Work DNS',
      servers: ['https://dns.nextdns.io/...'],
    })
  })

  // The agent names the server it could not make sense of, which is the only thing that
  // says which of four boxes to fix.
  it('shows the agent reason for refusing a server', async () => {
    const { getByRole, getByLabelText, getByText, agent } = await openDialog()
    agent.set(
      'POST /api/dns/profiles',
      failWith(400, 'dns.example.com: a bare hostname cannot be resolved by the resolver that is about to change'),
    )

    fireEvent.change(getByLabelText('Name'), { target: { value: 'Broken' } })
    fireEvent.change(getByLabelText('Server'), { target: { value: 'dns.example.com' } })
    fireEvent.click(getByRole('button', { name: 'Add profile' }))
    await settle()

    expect(getByText(/a bare hostname cannot be resolved/)).toBeInTheDocument()
    expect(getByRole('dialog')).toBeInTheDocument()
  })

  it('closes on Escape', async () => {
    const { queryByRole } = await openDialog()

    pressEscape()
    await settle()

    expect(queryByRole('dialog')).not.toBeInTheDocument()
  })
})
