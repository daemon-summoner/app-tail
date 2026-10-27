// SPDX-License-Identifier: MIT

import { fireEvent } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'

import { renderScoped } from '../../test/agent'
import { ChoicePicker, type Choice } from './ChoicePicker'

const CHOICES: Choice[] = [
  { value: '', label: 'Out of this machine', detail: 'The way it always has.' },
  { value: 'tn_office', label: 'Office', detail: 'A WireGuard connection.' },
  { value: 'tn_lab', label: 'Lab', detail: 'A WireGuard connection.' },
]

function picker(overrides: Partial<Parameters<typeof ChoicePicker>[0]> = {}) {
  const onChoose = vi.fn()
  const view = renderScoped(
    <ChoicePicker
      legend="Internet traffic"
      name="egress.mode"
      choices={CHOICES}
      selected="tn_office"
      disabled={false}
      loading="Loading connections…"
      empty="Nothing to choose from."
      onChoose={onChoose}
      {...overrides}
    />,
  )
  const toggle = () => view.container.querySelector<HTMLButtonElement>('.picker-current')!
  return { ...view, onChoose, toggle, open: () => fireEvent.click(toggle()) }
}

describe('what the closed control says', () => {
  it('is the choice in force, name and meaning both', () => {
    const view = picker()

    expect(view.toggle()).toHaveTextContent('Office')
    expect(view.toggle()).toHaveTextContent('A WireGuard connection.')
    expect(view.container.querySelectorAll('.choice-row')).toHaveLength(0)
  })

  // A stored value the agent no longer offers. Showing nothing would read as a machine
  // nobody has configured rather than one configured for something that is gone.
  it('names a stored value none of the choices carries', () => {
    const view = picker({ selected: 'tn_removed' })

    expect(view.toggle()).toHaveTextContent('tn_removed')
  })

  // Nothing is choosable yet, so the control says what it is waiting for and refuses the
  // click rather than opening onto an empty list.
  it('waits, disabled, while the choices are still being read', () => {
    const view = picker({ choices: undefined })

    expect(view.toggle()).toHaveTextContent('Loading connections…')
    expect(view.toggle()).toBeDisabled()
  })

  it('says so, disabled, when there is nothing to choose from', () => {
    const view = picker({ choices: [] })

    expect(view.toggle()).toHaveTextContent('Nothing to choose from.')
    expect(view.toggle()).toBeDisabled()
  })

  // A write is in flight and the answer decides what the rows mean, so the list may be read
  // and not acted on.
  it('refuses to open while a write is in flight', () => {
    const view = picker({ disabled: true })

    expect(view.toggle()).toBeDisabled()
  })
})

describe('opening and closing the list', () => {
  it('offers every choice and marks the one in force', () => {
    const view = picker()
    view.open()

    const rows = [...view.container.querySelectorAll<HTMLInputElement>('.choice-row input')]
    expect(rows.map((row) => row.value)).toEqual(['', 'tn_office', 'tn_lab'])
    expect(rows.filter((row) => row.checked).map((row) => row.value)).toEqual(['tn_office'])
  })

  it('hands the chosen value on and closes', () => {
    const view = picker()
    view.open()

    fireEvent.click(view.container.querySelector<HTMLInputElement>('input[value="tn_lab"]')!)

    expect(view.onChoose).toHaveBeenCalledWith('tn_lab')
    expect(view.container.querySelectorAll('.choice-row')).toHaveLength(0)
  })

  // A click anywhere else is a decision not to choose. Left open, the list would stand over
  // the rest of the card behind whatever was clicked next.
  it('closes on a click outside without choosing anything', () => {
    const view = picker()
    view.open()

    fireEvent.pointerDown(document.body)

    expect(view.container.querySelectorAll('.choice-row')).toHaveLength(0)
    expect(view.onChoose).not.toHaveBeenCalled()
  })

  // The way out for somebody who opened it from the keyboard, who has no elsewhere to
  // click. Focus goes back to the control they opened, not to the top of the page.
  it('closes on Escape and returns the focus to the control', () => {
    const view = picker()
    view.open()

    fireEvent.keyDown(document, { key: 'Escape' })

    expect(view.container.querySelectorAll('.choice-row')).toHaveLength(0)
    expect(document.activeElement).toBe(view.toggle())
    expect(view.onChoose).not.toHaveBeenCalled()
  })

  // The keyboard lands on the row in force, so the arrow keys move from where the machine
  // is rather than from the top of a list of destinations it is not using.
  it('puts the focus on the row in force when it opens', () => {
    const view = picker()
    view.open()

    expect((document.activeElement as HTMLInputElement | null)?.value).toBe('tn_office')
  })
})
