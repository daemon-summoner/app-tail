// SPDX-License-Identifier: MIT

import { fireEvent } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'

import { failWith, noContent, pressEscape, renderAgent, reply, settle } from '../test/agent'
import { DnsBlockListManager } from './DnsBlockListManager'
import type { DNSBlockListView } from '../api'

/** The catalog as it stands after somebody has added one of their own. */
function catalog(): DNSBlockListView[] {
  return [
    {
      id: 'hagezi-pro',
      provider: 'Hagezi',
      name: 'Hagezi Pro',
      url: 'https://example.test/pro.txt',
      format: 'abp',
      builtIn: true,
      enabled: true,
      rules: 152_403,
      skipped: 12,
    },
    {
      id: 'work',
      provider: 'Your lists',
      name: 'Work list',
      url: 'https://lists.example.test/work.txt',
      format: 'auto',
      builtIn: false,
      enabled: false,
      rules: 0,
      skipped: 0,
    },
  ]
}

// The shipped lists are what blocking falls back to when a list somebody added is the one
// that broke a site, so nothing here may offer to remove them.
it('offers no way to edit or delete a built-in list', async () => {
  const { queryByLabelText, getByLabelText } = await renderAgent(
    <DnsBlockListManager lists={catalog()} onChanged={() => {}} />,
  )

  expect(queryByLabelText('Delete Hagezi Pro')).not.toBeInTheDocument()
  expect(queryByLabelText('Edit Hagezi Pro')).not.toBeInTheDocument()
  expect(getByLabelText('Delete Work list')).toBeInTheDocument()
})

it('removes a list and tells the card to re-read the catalog', async () => {
  const changed = vi.fn()
  const { getByLabelText, agent } = await renderAgent(
    <DnsBlockListManager lists={catalog()} onChanged={changed} />,
    { 'DELETE /api/dns/block/lists': noContent() },
  )

  fireEvent.click(getByLabelText('Delete Work list'))
  await settle()

  expect(agent.urlOf('DELETE /api/dns/block/lists')).toBe('/api/dns/block/lists/work')
  expect(changed).toHaveBeenCalled()
})

// Deleting a list that is switched on is refused by the agent until it is switched off. A
// refusal that vanished would read as a delete that worked.
it('states a refused delete rather than swallowing it', async () => {
  const { getByLabelText, getByText } = await renderAgent(
    <DnsBlockListManager lists={catalog()} onChanged={() => {}} />,
    {
      'DELETE /api/dns/block/lists': failWith(400, 'Work list is switched on'),
    },
  )

  fireEvent.click(getByLabelText('Delete Work list'))
  await settle()

  expect(getByText(/Work list is switched on/)).toBeInTheDocument()
})

describe('the list dialog', () => {
  const added: DNSBlockListView = {
    id: 'ads',
    provider: 'Your lists',
    name: 'Ads',
    url: 'https://lists.example.test/ads.txt',
    format: 'auto',
    builtIn: false,
    enabled: false,
    rules: 0,
    skipped: 0,
  }

  const openDialog = async (label = 'Add a list') => {
    const view = await renderAgent(
      <DnsBlockListManager lists={catalog()} onChanged={() => {}} />,
      {
        'POST /api/dns/block/lists': reply(201, added),
        'PUT /api/dns/block/lists': reply(200, catalog()[1]),
      },
    )
    fireEvent.click(view.getByRole('button', { name: label }))
    await settle()
    return view
  }

  it('refuses to save a list with no name or no address', async () => {
    const { getByRole, getByLabelText } = await openDialog()

    expect(getByRole('button', { name: 'Add list' })).toBeDisabled()

    fireEvent.change(getByLabelText('Name'), { target: { value: 'Ads' } })
    expect(getByRole('button', { name: 'Add list' })).toBeDisabled()

    fireEvent.change(getByLabelText('Address'), {
      target: { value: 'https://lists.example.test/ads.txt' },
    })
    expect(getByRole('button', { name: 'Add list' })).toBeEnabled()
  })

  // Reading the file is right for almost every list, so it is what a list added without a
  // decision carries. A form that sent nothing would leave the agent guessing at parse time
  // rather than at fetch time.
  it('sends the name, the address and how the file is to be read', async () => {
    const { getByRole, getByLabelText, agent } = await openDialog()

    fireEvent.change(getByLabelText('Name'), { target: { value: 'Ads' } })
    fireEvent.change(getByLabelText('Address'), {
      target: { value: 'https://lists.example.test/ads.txt' },
    })
    fireEvent.change(getByLabelText('Written as'), { target: { value: 'hosts' } })
    fireEvent.click(getByRole('button', { name: 'Add list' }))
    await settle()

    expect(agent.bodyOf('POST /api/dns/block/lists')).toEqual({
      name: 'Ads',
      url: 'https://lists.example.test/ads.txt',
      format: 'hosts',
    })
  })

  // The id has to survive an edit: the enabled set points at it, so a save that minted a
  // new one would leave blocking using a list nothing switches on any more.
  it('edits in place, keeping the id the settings point at', async () => {
    const { getByRole, getByLabelText, agent } = await openDialog('Edit Work list')

    fireEvent.change(getByLabelText('Address'), {
      target: { value: 'https://lists.example.test/work-v2.txt' },
    })
    fireEvent.click(getByRole('button', { name: 'Save changes' }))
    await settle()

    expect(agent.urlOf('PUT /api/dns/block/lists')).toBe('/api/dns/block/lists/work')
    expect(agent.bodyOf('PUT /api/dns/block/lists')).toEqual({
      name: 'Work list',
      url: 'https://lists.example.test/work-v2.txt',
      format: 'auto',
    })
  })

  it('shows the agent reason for refusing an address', async () => {
    const { getByRole, getByLabelText, getByText, agent } = await openDialog()
    agent.set(
      'POST /api/dns/block/lists',
      failWith(400, 'url: a blocklist is downloaded over http or https'),
    )

    fireEvent.change(getByLabelText('Name'), { target: { value: 'Broken' } })
    fireEvent.change(getByLabelText('Address'), { target: { value: 'ftp://example.test/list' } })
    fireEvent.click(getByRole('button', { name: 'Add list' }))
    await settle()

    expect(getByText(/downloaded over http or https/)).toBeInTheDocument()
    expect(getByRole('dialog')).toBeInTheDocument()
  })

  it('closes on Escape', async () => {
    const { queryByRole } = await openDialog()

    pressEscape()
    await settle()

    expect(queryByRole('dialog')).not.toBeInTheDocument()
  })
})
