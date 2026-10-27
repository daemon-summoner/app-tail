// SPDX-License-Identifier: MIT

import { fireEvent } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'

import { pressEscape, renderScoped } from '../test/agent'
import { ConfirmDialog } from './ConfirmDialog'

function build(overrides: Partial<Parameters<typeof ConfirmDialog>[0]> = {}) {
  return (
    <ConfirmDialog
      title="Restart app-tail?"
      confirmLabel="Restart"
      onConfirm={() => {}}
      onClose={() => {}}
      {...overrides}
    >
      <p>Every open connection is closed.</p>
    </ConfirmDialog>
  )
}

describe('ConfirmDialog', () => {
  it('renders a labelled modal dialog', () => {
    const view = renderScoped(build())

    const dialog = view.getByRole('dialog')
    expect(dialog).toHaveAttribute('aria-modal', 'true')
    expect(dialog).toHaveAccessibleName('Restart app-tail?')
    expect(view.getByText('Every open connection is closed.')).toBeInTheDocument()
  })

  // The button is read on its own by anyone tabbing to it, so it says what happens
  // rather than "OK".
  it('names the action on its confirm button', () => {
    const onConfirm = vi.fn()
    const view = renderScoped(build({ onConfirm }))

    fireEvent.click(view.getByRole('button', { name: 'Restart' }))

    expect(onConfirm).toHaveBeenCalledTimes(1)
  })

  it('weights a destructive confirm', () => {
    const view = renderScoped(build({ destructive: true }))

    expect(view.getByRole('button', { name: 'Restart' })).toHaveClass('danger')
  })

  // A slow action with the dialog already dismissed looks like a click that did
  // nothing, so the dialog stays and says what it is doing.
  it('holds itself open and disabled while the action runs', () => {
    const onConfirm = vi.fn()
    const view = renderScoped(
      build({ busy: true, busyLabel: 'Restarting…', onConfirm }),
    )

    const confirm = view.getByRole('button', { name: 'Restarting…' })
    expect(confirm).toBeDisabled()

    fireEvent.click(confirm)
    expect(onConfirm).not.toHaveBeenCalled()
  })

  it('dismisses from the backdrop but not from inside', () => {
    const onClose = vi.fn()
    const view = renderScoped(build({ onClose }))

    fireEvent.click(view.getByRole('dialog'))
    expect(onClose).not.toHaveBeenCalled()

    fireEvent.click(view.container.querySelector('.scrim')!)
    expect(onClose).toHaveBeenCalledTimes(1)
  })

  it('dismisses from Cancel, from Close and from Escape', () => {
    const onClose = vi.fn()
    const view = renderScoped(build({ onClose }))

    fireEvent.click(view.getByRole('button', { name: 'Cancel' }))
    fireEvent.click(view.getByLabelText('Close'))
    pressEscape()

    expect(onClose).toHaveBeenCalledTimes(3)
  })

  // The keydown listener lives on window, which outlives the component. A missing
  // cleanup leaves a closed dialog answering every Escape the user presses afterwards.
  it('stops answering Escape once unmounted', () => {
    const onClose = vi.fn()
    const view = renderScoped(build({ onClose }))

    view.unmount()
    pressEscape()

    expect(onClose).not.toHaveBeenCalled()
  })
})
