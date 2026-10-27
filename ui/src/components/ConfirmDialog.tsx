// SPDX-License-Identifier: MIT

// The question asked before something the user cannot undo by clicking again.
//
// It carries the same dismissal wiring every other overlay has -- backdrop, labelled
// Close, Escape -- so there is never a modal on this page that has to be answered to
// get out of.

import { useEffect, type ReactNode } from 'react'
import { Scrim } from './primitives'
import { CloseIcon } from './shell/icons'

interface ConfirmDialogProps {
  title: string
  /** confirmLabel says what will happen, not "OK": the button is read on its own by
   *  anyone tabbing to it. */
  confirmLabel: string
  /** destructive weights the confirm button for something that interrupts work in
   *  progress rather than merely changing a setting. */
  destructive?: boolean | undefined
  /** busy holds the dialog open while the action runs, so a slow answer is not a
   *  dialog that appears to have ignored the click. */
  busy?: boolean | undefined
  busyLabel?: string | undefined
  onConfirm: () => void
  onClose: () => void
  children: ReactNode
}

export function ConfirmDialog({
  title,
  confirmLabel,
  destructive,
  busy,
  busyLabel,
  onConfirm,
  onClose,
  children,
}: ConfirmDialogProps) {
  // Window-level, because focus may be on the confirm button or nowhere in particular.
  // Removed on unmount: a listener left behind closes whatever overlay comes next.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose()
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [onClose])

  return (
    <Scrim onClose={onClose}>
      <div className="modal confirm" role="dialog" aria-modal="true" aria-label={title}>
        <div className="overlay-head">
          <h2>{title}</h2>
          <span className="spacer" />
          <button className="btn ghost small square" onClick={onClose} aria-label="Close">
            <CloseIcon />
          </button>
        </div>

        <div className="overlay-body">{children}</div>

        <div className="overlay-foot">
          <button className="btn" onClick={onClose}>
            Cancel
          </button>
          <button
            className={destructive ? 'btn danger' : 'btn primary'}
            disabled={busy ?? false}
            onClick={onConfirm}
          >
            {busy ? (busyLabel ?? 'Working…') : confirmLabel}
          </button>
        </div>
      </div>
    </Scrim>
  )
}
