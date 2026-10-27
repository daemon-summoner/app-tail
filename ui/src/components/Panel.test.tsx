// SPDX-License-Identifier: MIT

import { fireEvent } from '@testing-library/react'
import { describe, expect, it } from 'vitest'

import { renderScoped } from '../test/agent'
import { Panel } from './Panel'

describe('Panel', () => {
  it('is a landmark named by its heading', () => {
    const view = renderScoped(<Panel title="Subnet routes">body</Panel>)

    expect(view.getByRole('region', { name: 'Subnet routes' })).toBeInTheDocument()
    expect(view.getByRole('heading', { name: 'Subnet routes' })).toBeInTheDocument()
  })

  // Forwards is the one card whose heading and region name differ: the strip above it
  // already carries "Port forwards", and two regions answering to one name is as
  // confusing to query as it is to hear read aloud.
  it('takes a region name that differs from the heading', () => {
    const view = renderScoped(
      <Panel title="Forwards" regionLabel="Port forwards">
        body
      </Panel>,
    )

    expect(view.getByRole('region', { name: 'Port forwards' })).toBeInTheDocument()
    expect(view.getByRole('heading', { name: 'Forwards' })).toBeInTheDocument()
  })

  // The colour is the fast read, the word is the actual answer. A chip that shipped
  // only a dot would carry its meaning by hue alone.
  it('pairs the status colour with a word', () => {
    const view = renderScoped(
      <Panel title="Tailnet proxy" status={{ tone: 'running', label: 'listening' }}>
        body
      </Panel>,
    )

    const chip = view.container.querySelector('.status.running')
    expect(chip).toHaveTextContent('listening')
    expect(chip?.querySelector('.dot')).toHaveAttribute('aria-hidden', 'true')
  })

  it('sets the state detail apart in monospace', () => {
    const view = renderScoped(
      <Panel
        title="Tailnet proxy"
        status={{ tone: 'running', label: 'listening', detail: '127.0.0.1:1080' }}
      >
        body
      </Panel>,
    )

    expect(view.container.querySelector('.status .mono')).toHaveTextContent('127.0.0.1:1080')
  })

  it('offers what the card always does behind an info button', () => {
    const view = renderScoped(
      <Panel title="DNS" info={<p>Only app-tail resolves through it.</p>}>
        body
      </Panel>,
    )

    expect(view.queryByText('Only app-tail resolves through it.')).not.toBeInTheDocument()

    fireEvent.click(view.getByRole('button', { name: 'About DNS' }))

    expect(view.getByText('Only app-tail resolves through it.')).toBeInTheDocument()
  })

  it('carries no info button when the card has nothing permanent to say', () => {
    const view = renderScoped(<Panel title="DNS">body</Panel>)

    expect(view.container.querySelector('.info-trigger')).toBeNull()
  })

  it('places the module switch and the actions in the head', () => {
    const view = renderScoped(
      <Panel
        title="Tailnet proxy"
        controls={<button>Switch</button>}
        actions={<button>Check</button>}
      >
        body
      </Panel>,
    )

    const head = view.container.querySelector('.panel-head')
    expect(head).toContainElement(view.getByRole('button', { name: 'Switch' }))
    expect(head).toContainElement(view.getByRole('button', { name: 'Check' }))
  })

  // A card that is off has a head and a switch and nothing to put in a body. An empty
  // padded box under it reads as content that failed to load.
  it('renders no body when the card has none', () => {
    const view = renderScoped(<Panel title="Subnet routes" />)

    expect(view.container.querySelector('.panel-body')).toBeNull()
  })

  it('takes an anchor id so the mode strip can reach it', () => {
    const view = renderScoped(
      <Panel title="Network interface" id="interface">
        body
      </Panel>,
    )

    expect(view.container.querySelector('#interface')).toHaveClass('panel')
  })

  it('spans the deck when the card lays out columns of its own', () => {
    const view = renderScoped(
      <Panel title="Subnet routes" wide>
        body
      </Panel>,
    )

    expect(view.container.querySelector('.panel')).toHaveClass('wide')
  })
})
