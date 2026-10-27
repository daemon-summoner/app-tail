// SPDX-License-Identifier: MIT

// A picker that shows the choice in force and opens the rest on a click.
//
// Two of these are the first thing on the dashboard -- which resolver this machine uses,
// and which connection carries its internet traffic -- and both have the same difficulty:
// the names alone do not tell the choices apart. "Work" and "Home" are two resolvers, and
// which servers they resolve through is the whole question; "Office" and "Lab" are two
// connections, and where each one leaves from is the whole question. So every row carries a
// second line, including the closed row, which is what a native select cannot do.
//
// Closed, it answers "what is it doing"; open, it answers "what else could it do". Both
// lists standing open answered the second question at the cost of the first.

import { useEffect, useId, useRef, useState, type ReactNode } from 'react'

/** One row: the value written when it is chosen, its name, and what it means. */
export interface Choice {
  /** The stored value this row stands for. Empty is a legitimate value -- it is how the
   *  internet picker says "out of this machine" -- so rows are keyed by it as written. */
  value: string
  label: string
  detail: string
}

export function ChoicePicker({
  legend,
  /** name groups the radios, so the arrow keys move within one picker rather than across
   *  both of them. */
  name,
  /** choices is undefined while they are still being read, which is a different thing
   *  from a picker with nothing to offer. */
  choices,
  selected,
  disabled,
  loading,
  empty,
  onChoose,
  children,
}: {
  legend: string
  name: string
  choices: readonly Choice[] | undefined
  selected: string
  disabled: boolean
  loading: string
  empty: string
  onChoose: (value: string) => void
  /** children are the notices this picker's own write produced. They stay under the closed
   *  row rather than inside the list: a connection that is not carrying the traffic is the
   *  state of the choice in force, and closing the list must not hide it. */
  children?: ReactNode
}) {
  const [open, setOpen] = useState(false)
  const listId = useId()
  const root = useRef<HTMLDivElement>(null)
  const list = useRef<HTMLFieldSetElement>(null)
  const toggle = useRef<HTMLButtonElement>(null)

  // A click anywhere else is a decision not to choose, and so is Escape. Without either the
  // list stays open behind whatever was clicked next, over the rest of the card.
  useEffect(() => {
    if (!open) return
    const close = () => {
      setOpen(false)
      toggle.current?.focus()
    }
    const onDown = (event: PointerEvent) => {
      if (!root.current?.contains(event.target as Node)) setOpen(false)
    }
    const onKey = (event: KeyboardEvent) => {
      if (event.key === 'Escape') close()
    }
    document.addEventListener('pointerdown', onDown)
    document.addEventListener('keydown', onKey)
    return () => {
      document.removeEventListener('pointerdown', onDown)
      document.removeEventListener('keydown', onKey)
    }
  }, [open])

  // The keyboard lands on the row in force, so the arrow keys move from where the machine
  // is rather than from the top of the list.
  useEffect(() => {
    if (!open) return
    list.current?.querySelector<HTMLInputElement>('input:checked')?.focus()
  }, [open])

  const current = choices?.find((choice) => choice.value === selected)
  const ready = choices !== undefined && choices.length > 0

  const choose = (value: string) => {
    setOpen(false)
    toggle.current?.focus()
    onChoose(value)
  }

  return (
    <div className="choice-picker" ref={root}>
      <span className="picker-legend" id={`${listId}-legend`}>
        {legend}
      </span>

      <button
        type="button"
        className="picker-current"
        ref={toggle}
        aria-expanded={open}
        aria-controls={listId}
        aria-describedby={`${listId}-legend`}
        disabled={disabled || !ready}
        onClick={() => setOpen((was) => !was)}
      >
        <span className="title">
          {choices === undefined
            ? loading
            : choices.length === 0
              ? empty
              : // A stored value none of the choices names: the setting says something the
                // agent no longer offers, and saying "none" would read as a machine nobody
                // has configured rather than one configured for something that is gone.
                (current?.label ?? selected ?? '')}
        </span>
        <span className="sub mono">{current?.detail ?? ''}</span>
        <span className="picker-caret" aria-hidden="true" />
      </button>

      {open && choices !== undefined ? (
        <fieldset className="choice-list" id={listId} ref={list}>
          <legend>{legend}</legend>
          {choices.map((choice) => (
            <label key={choice.value} className="choice-row">
              <input
                type="radio"
                name={name}
                value={choice.value}
                checked={choice.value === selected}
                disabled={disabled}
                onChange={() => choose(choice.value)}
              />
              <span className="title">{choice.label}</span>
              <span className="sub mono">{choice.detail}</span>
            </label>
          ))}
        </fieldset>
      ) : null}

      {children}
    </div>
  )
}
