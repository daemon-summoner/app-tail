// SPDX-License-Identifier: MIT

// The dashboard's one affordance for text that is permanently true.
//
// A card states what is wrong right now inline, where it cannot be missed, and keeps
// what the feature always does -- what it changes about the machine, what it will not
// carry -- behind this. The split is what lets a card lead with its live data instead
// of with three paragraphs that read the same on every machine.

import { useEffect, useId, useRef, useState, type ReactNode } from 'react'
import { InfoIcon } from './shell/icons'

interface InfoPopoverProps {
  /** label names what is being explained. It becomes the button's accessible name,
   *  because "info" repeated down the page tells a screen reader nothing. */
  label: string
  /** align is which edge of the trigger the panel hangs from. A trigger near the right
   *  of its card needs 'end' or the panel runs off the side. */
  align?: 'start' | 'end' | undefined
  children: ReactNode
}

export function InfoPopover({ label, align = 'start', children }: InfoPopoverProps) {
  const [open, setOpen] = useState(false)
  const triggerRef = useRef<HTMLButtonElement>(null)
  const wrapRef = useRef<HTMLSpanElement>(null)
  const bodyId = useId()

  // Both listeners live on window so a click or an Escape anywhere closes this, and
  // both are removed with the panel: one left behind would answer for a popover that
  // is no longer on the page.
  useEffect(() => {
    if (!open) return undefined

    const close = () => {
      setOpen(false)
      triggerRef.current?.focus()
    }
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') close()
    }
    // mousedown rather than click: a click that starts inside the panel and ends
    // outside it is a drag over text, not a dismissal.
    const onPointer = (e: MouseEvent) => {
      if (!wrapRef.current?.contains(e.target as Node)) setOpen(false)
    }

    window.addEventListener('keydown', onKey)
    window.addEventListener('mousedown', onPointer)
    return () => {
      window.removeEventListener('keydown', onKey)
      window.removeEventListener('mousedown', onPointer)
    }
  }, [open])

  return (
    <span className="info" ref={wrapRef}>
      <button
        type="button"
        ref={triggerRef}
        className="info-trigger"
        aria-label={`About ${label}`}
        aria-expanded={open}
        aria-controls={bodyId}
        onClick={() => setOpen((was) => !was)}
      >
        <InfoIcon />
      </button>

      {/* Absent from the tree while closed rather than hidden by a rule. Content that
          is only invisible is still read out, still tabbed into, and still found by a
          test -- which would report prose as reachable that nobody can see. */}
      {open ? (
        <span className={`info-body ${align}`} id={bodyId}>
          {children}
        </span>
      ) : null}
    </span>
  )
}

/** InfoList is the shape most of these take: the agent's own sentences about a module,
 *  one per line. Kept here so every card renders that list identically. */
export function InfoList({ items }: { items: readonly string[] }) {
  if (items.length === 0) return null
  return (
    <ul className="info-list">
      {items.map((item) => (
        <li key={item}>{item}</li>
      ))}
    </ul>
  )
}
