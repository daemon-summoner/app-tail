// SPDX-License-Identifier: MIT

import { fireEvent } from '@testing-library/react'
import { describe, expect, it } from 'vitest'

import { pressEscape, renderScoped } from '../test/agent'
import { InfoList, InfoPopover } from './InfoPopover'

const PROSE = 'It changes the machine, not just app-tail.'

function open(view: ReturnType<typeof renderScoped>) {
  fireEvent.click(view.getByRole('button', { name: 'About Network interface' }))
}

describe('InfoPopover', () => {
  // The whole point of moving prose behind this is that it is out of the way until
  // asked for. Content that is merely hidden by a stylesheet is still read out by a
  // screen reader, still tabbed into, and still found by every other test in this
  // suite -- which would report the sentence as reachable when nobody can see it.
  it('keeps its content out of the document until it is opened', () => {
    const view = renderScoped(
      <InfoPopover label="Network interface">
        <p>{PROSE}</p>
      </InfoPopover>,
    )

    expect(view.queryByText(PROSE)).not.toBeInTheDocument()
    expect(view.container.textContent).not.toContain(PROSE)
  })

  it('reveals the content on click and hides it again', () => {
    const view = renderScoped(
      <InfoPopover label="Network interface">
        <p>{PROSE}</p>
      </InfoPopover>,
    )

    open(view)
    expect(view.getByText(PROSE)).toBeInTheDocument()

    open(view)
    expect(view.queryByText(PROSE)).not.toBeInTheDocument()
  })

  // A real button is what makes Enter and Space work without a keydown handler of its
  // own, which is the whole reason the trigger is not a styled span.
  it('is a button that reports whether it is open', () => {
    const view = renderScoped(
      <InfoPopover label="Network interface">
        <p>{PROSE}</p>
      </InfoPopover>,
    )
    const trigger = view.getByRole('button', { name: 'About Network interface' })

    expect(trigger).toHaveAttribute('type', 'button')
    expect(trigger).toHaveAttribute('aria-expanded', 'false')

    open(view)

    expect(trigger).toHaveAttribute('aria-expanded', 'true')
    expect(trigger.getAttribute('aria-controls')).toBe(
      view.getByText(PROSE).parentElement?.getAttribute('id'),
    )
  })

  // The dashboard already has one dialog at a time and several suites query for it in
  // the singular. An info panel announcing itself as a second one makes those
  // ambiguous, and it is a disclosure rather than a dialog in any case.
  it('is not announced as a dialog', () => {
    const view = renderScoped(
      <InfoPopover label="Network interface">
        <p>{PROSE}</p>
      </InfoPopover>,
    )

    open(view)

    expect(view.queryByRole('dialog')).not.toBeInTheDocument()
  })

  it('closes on Escape and puts focus back on its trigger', () => {
    const view = renderScoped(
      <InfoPopover label="Network interface">
        <p>{PROSE}</p>
      </InfoPopover>,
    )
    const trigger = view.getByRole('button', { name: 'About Network interface' })

    open(view)
    // Somewhere else on the page, so the assertion below proves focus was moved back
    // rather than that it simply never left.
    document.body.focus()

    pressEscape()

    expect(view.queryByText(PROSE)).not.toBeInTheDocument()
    expect(document.activeElement).toBe(trigger)
  })

  it('closes on a click outside it but not on one inside', () => {
    const view = renderScoped(
      <InfoPopover label="Network interface">
        <p>{PROSE}</p>
      </InfoPopover>,
    )

    open(view)

    // Selecting the text to copy it must not dismiss what is being read.
    fireEvent.mouseDown(view.getByText(PROSE))
    expect(view.getByText(PROSE)).toBeInTheDocument()

    fireEvent.mouseDown(document.body)
    expect(view.queryByText(PROSE)).not.toBeInTheDocument()
  })

  // Both listeners sit on window, which outlives the component. One left behind keeps
  // answering for a popover that is no longer on the page.
  it('stops listening once unmounted', () => {
    const view = renderScoped(
      <InfoPopover label="Network interface">
        <p>{PROSE}</p>
      </InfoPopover>,
    )
    open(view)

    view.unmount()

    expect(() => {
      pressEscape()
      fireEvent.mouseDown(document.body)
    }).not.toThrow()
  })

  it('hangs from the edge the caller asked for', () => {
    const view = renderScoped(
      <InfoPopover label="Network interface" align="end">
        <p>{PROSE}</p>
      </InfoPopover>,
    )

    open(view)

    expect(view.container.querySelector('.info-body')).toHaveClass('end')
  })
})

describe('InfoList', () => {
  it('renders one item per sentence the agent served', () => {
    const view = renderScoped(<InfoList items={['First limit.', 'Second limit.']} />)

    const items = view.container.querySelectorAll('.info-list li')
    expect([...items].map((li) => li.textContent)).toEqual(['First limit.', 'Second limit.'])
  })

  // An empty limits array is the common case on a platform with nothing to warn about,
  // and an empty bulleted list reads as a load that failed.
  it('renders nothing when the agent served no sentences', () => {
    const view = renderScoped(<InfoList items={[]} />)

    expect(view.container.querySelector('.info-list')).toBeNull()
  })
})
