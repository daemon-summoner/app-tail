// SPDX-License-Identifier: MIT

import { fireEvent } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'

import { pressEscape, renderAgent } from '../test/agent'
import { ForwardDialog } from './ForwardDialog'
import { ConfirmDialog } from './ConfirmDialog'
import { TagSetupDialog } from './TagSetupDialog'

// The three overlays each carry their own copy of the same dismissal wiring: the
// shared Scrim, a labelled Close button, and a window-level Escape listener. This is
// the one file that holds all three to the same contract, so a new overlay -- or an
// edit to one of them -- cannot quietly lose a way out.
describe.each([
  [
    'ConfirmDialog',
    (onClose: () => void) => (
      <ConfirmDialog title="Restart app-tail?" confirmLabel="Restart" onConfirm={() => {}} onClose={onClose}>
        <p>Every open connection is closed.</p>
      </ConfirmDialog>
    ),
    'Close',
    'Restart app-tail?',
  ],
  [
    'ForwardDialog',
    (onClose: () => void) => (
      <ForwardDialog editing={undefined} onClose={onClose} onSaved={() => {}} />
    ),
    'Close',
    'Add forward',
  ],
  ['TagSetupDialog', (onClose: () => void) => <TagSetupDialog onClose={onClose} />, 'Close', 'Tag setup'],
])('%s', (_name, build, closeLabel, dialogLabel) => {
  it('renders a labelled modal dialog once the agent has answered', async () => {
    const { getByRole, container } = await renderAgent(build(() => {}))

    const dialog = getByRole('dialog')
    expect(dialog).toBeInTheDocument()
    // Without aria-modal a screen reader keeps reading the dashboard behind the
    // overlay, and without a label it announces only "dialog".
    expect(dialog).toHaveAttribute('aria-modal', 'true')
    expect(dialog).toHaveAccessibleName(dialogLabel)
    expect(container.querySelector('.scrim')).toHaveAttribute('role', 'presentation')
  })

  it('dismisses from the backdrop but not from inside', async () => {
    const onClose = vi.fn()
    const { getByRole, container } = await renderAgent(build(onClose))

    // The click bubbles to the backdrop's handler, so only the target comparison
    // keeps a click on a form control -- or a drag released over the backdrop --
    // from throwing away everything the user typed.
    fireEvent.click(getByRole('dialog'))
    expect(onClose).not.toHaveBeenCalled()

    fireEvent.click(container.querySelector('.scrim')!)
    expect(onClose).toHaveBeenCalledTimes(1)
  })

  it('dismisses from its Close button', async () => {
    const onClose = vi.fn()
    const { getByLabelText } = await renderAgent(build(onClose))

    fireEvent.click(getByLabelText(closeLabel))

    expect(onClose).toHaveBeenCalledTimes(1)
  })

  it('dismisses on Escape', async () => {
    const onClose = vi.fn()
    await renderAgent(build(onClose))

    pressEscape()

    expect(onClose).toHaveBeenCalledTimes(1)
  })

  // The keydown listener lives on window, which outlives the component. A missing
  // cleanup leaves a closed dialog still calling onClose on every Escape, so the
  // next overlay the user opens vanishes the moment they press it.
  it('stops answering Escape once unmounted', async () => {
    const onClose = vi.fn()
    const { unmount } = await renderAgent(build(onClose))

    unmount()
    pressEscape()

    expect(onClose).not.toHaveBeenCalled()
  })
})
