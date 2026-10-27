// SPDX-License-Identifier: MIT

import { fireEvent } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'

import { failWith, noContent, pressEscape, renderAgent, reply, settle } from '../test/agent'
import { IpsFeedManager } from './IpsFeedManager'
import type { IPSFeedView } from '../api'

/** The catalog as it stands after somebody has added one of their own. */
function catalog(): IPSFeedView[] {
  return [
    {
      id: 'firehol-level1',
      provider: 'FireHOL',
      name: 'FireHOL level 1',
      url: 'https://feeds.example.test/level1.netset',
      builtIn: true,
      enabled: true,
      rules: 4231,
      skipped: 18,
    },
    {
      id: 'work',
      provider: 'Your feeds',
      name: 'Work feed',
      url: 'https://feeds.example.test/work.txt',
      builtIn: false,
      enabled: false,
      rules: 0,
      skipped: 0,
    },
  ]
}

// The shipped feeds are what inspection falls back to when a feed somebody added is the one
// that refused a site, so nothing here may offer to remove them.
it('offers no way to edit or delete a built-in feed', async () => {
  const { queryByLabelText, getByLabelText } = await renderAgent(
    <IpsFeedManager feeds={catalog()} onChanged={() => {}} />,
  )

  expect(queryByLabelText('Delete FireHOL level 1')).not.toBeInTheDocument()
  expect(queryByLabelText('Edit FireHOL level 1')).not.toBeInTheDocument()
  expect(getByLabelText('Delete Work feed')).toBeInTheDocument()
})

it('removes a feed and tells the card to re-read the catalog', async () => {
  const changed = vi.fn()
  const { getByLabelText, agent } = await renderAgent(
    <IpsFeedManager feeds={catalog()} onChanged={changed} />,
    { 'DELETE /api/ips/feeds': noContent() },
  )

  fireEvent.click(getByLabelText('Delete Work feed'))
  await settle()

  expect(agent.urlOf('DELETE /api/ips/feeds')).toBe('/api/ips/feeds/work')
  expect(changed).toHaveBeenCalled()
})

// Deleting a feed that is switched on is refused by the agent until it is switched off. A
// refusal that vanished would read as a delete that worked.
it('states a refused delete rather than swallowing it', async () => {
  const { getByLabelText, getByText } = await renderAgent(
    <IpsFeedManager feeds={catalog()} onChanged={() => {}} />,
    { 'DELETE /api/ips/feeds': failWith(400, 'Work feed is switched on') },
  )

  fireEvent.click(getByLabelText('Delete Work feed'))
  await settle()

  expect(getByText(/Work feed is switched on/)).toBeInTheDocument()
})

describe('the feed dialog', () => {
  const added: IPSFeedView = {
    id: 'tor',
    provider: 'Your feeds',
    name: 'Tor exits',
    url: 'https://feeds.example.test/tor.txt',
    builtIn: false,
    enabled: false,
    rules: 0,
    skipped: 0,
  }

  const openDialog = async (label = 'Add a feed') => {
    const view = await renderAgent(<IpsFeedManager feeds={catalog()} onChanged={() => {}} />, {
      'POST /api/ips/feeds': reply(201, added),
      'PUT /api/ips/feeds': reply(200, catalog()[1]),
    })
    fireEvent.click(view.getByRole('button', { name: label }))
    await settle()
    return view
  }

  it('refuses to save a feed with no name or no address', async () => {
    const { getByRole, getByLabelText } = await openDialog()

    expect(getByRole('button', { name: 'Add feed' })).toBeDisabled()

    fireEvent.change(getByLabelText('Name'), { target: { value: 'Tor exits' } })
    expect(getByRole('button', { name: 'Add feed' })).toBeDisabled()

    fireEvent.change(getByLabelText('Address'), {
      target: { value: 'https://feeds.example.test/tor.txt' },
    })
    expect(getByRole('button', { name: 'Add feed' })).toBeEnabled()
  })

  // There is no format to choose here: every feed of this kind is one address or one network
  // per line, so a body carrying anything else would be a field the agent has to ignore.
  it('sends the name and the address, and nothing else', async () => {
    const { getByRole, getByLabelText, agent } = await openDialog()

    fireEvent.change(getByLabelText('Name'), { target: { value: 'Tor exits' } })
    fireEvent.change(getByLabelText('Address'), {
      target: { value: 'https://feeds.example.test/tor.txt' },
    })
    fireEvent.click(getByRole('button', { name: 'Add feed' }))
    await settle()

    expect(agent.bodyOf('POST /api/ips/feeds')).toEqual({
      name: 'Tor exits',
      url: 'https://feeds.example.test/tor.txt',
    })
  })

  // The id has to survive an edit: the enabled set points at it, so a save that minted a new
  // one would leave inspection using a feed nothing switches on any more.
  it('edits in place, keeping the id the settings point at', async () => {
    const { getByRole, getByLabelText, agent } = await openDialog('Edit Work feed')

    fireEvent.change(getByLabelText('Address'), {
      target: { value: 'https://feeds.example.test/work-v2.txt' },
    })
    fireEvent.click(getByRole('button', { name: 'Save changes' }))
    await settle()

    expect(agent.urlOf('PUT /api/ips/feeds')).toBe('/api/ips/feeds/work')
    expect(agent.bodyOf('PUT /api/ips/feeds')).toEqual({
      name: 'Work feed',
      url: 'https://feeds.example.test/work-v2.txt',
    })
  })

  it('shows the agent reason for refusing an address', async () => {
    const { getByRole, getByLabelText, getByText, agent } = await openDialog()
    agent.set(
      'POST /api/ips/feeds',
      failWith(400, 'url: a feed is downloaded over https so it cannot be rewritten in transit'),
    )

    fireEvent.change(getByLabelText('Name'), { target: { value: 'Broken' } })
    fireEvent.change(getByLabelText('Address'), { target: { value: 'http://example.test/feed' } })
    fireEvent.click(getByRole('button', { name: 'Add feed' }))
    await settle()

    expect(getByText(/cannot be rewritten in transit/)).toBeInTheDocument()
    expect(getByRole('dialog')).toBeInTheDocument()
  })

  it('closes on Escape', async () => {
    const { queryByRole } = await openDialog()

    pressEscape()
    await settle()

    expect(queryByRole('dialog')).not.toBeInTheDocument()
  })
})
