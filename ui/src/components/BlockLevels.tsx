// SPDX-License-Identifier: MIT

// A ladder of levels, lowest first, as one radiogroup.
//
// Choosing a rung is the whole decision for most people, so each one carries the sentence
// that says what it adds rather than only its name. What choosing does is the caller's:
// this holds the one-request-at-a-time state around it and shows the failure, so every
// ladder on the page behaves the same way and is found the same way from the keyboard.

import { useId, useState, type ReactNode } from 'react'

import { ApiError } from '../api'
import { Notice } from './primitives'

/** One rung. Every preset the agent serves has this shape, and so does a rung that names
 *  a combination of switches rather than a list. */
export interface BlockLevel {
  id: string
  name: string
  summary: string
  /** The rung to pick without reading the rest. At most one carries it. */
  recommended?: boolean | undefined
}

interface BlockLevelsProps {
  /** The name of the group, which is what a screen reader announces before the rungs. */
  title?: string
  levels: readonly BlockLevel[]
  /** The rung the machine is on, or none when it is on a combination that is nobody's rung. */
  chosen: string | undefined
  /** What choosing a rung does. A rejection is shown beneath the ladder; the radios stay on
   *  whatever `chosen` says, because the served view is the only truth about the position. */
  choose: (id: string) => Promise<unknown>
  /** The sentence under the rungs: what a level does, or that the machine is on none. */
  hint: ReactNode
  /** Held while the caller is doing something of its own that the rungs must wait for. */
  busy?: boolean | undefined
}

export function BlockLevels({ title = 'Level', levels, chosen, choose, hint, busy }: BlockLevelsProps) {
  const id = useId()
  const [choosing, setChoosing] = useState(false)
  const [error, setError] = useState<string | undefined>(undefined)
  if (levels.length === 0) return null

  const pick = async (level: string) => {
    setChoosing(true)
    setError(undefined)
    try {
      await choose(level)
    } catch (cause) {
      setError(cause instanceof ApiError ? cause.message : String(cause))
    } finally {
      setChoosing(false)
    }
  }

  const disabled = choosing || busy === true
  return (
    <div className="block-levels-field">
      <span className="block-levels-title" id={id}>
        {title}
      </span>
      <div className="block-levels" role="radiogroup" aria-labelledby={id}>
        {levels.map((level) => {
          const on = level.id === chosen
          return (
            // A radio rather than a button: these are one choice with several positions,
            // and that is what somebody driving this from the keyboard expects to find.
            <label key={level.id} className={on ? 'block-level chosen' : 'block-level'}>
              <input
                type="radio"
                name={id}
                value={level.id}
                checked={on}
                disabled={disabled}
                onChange={() => void pick(level.id)}
              />
              <span className="block-level-name">
                {level.name}
                {level.recommended ? <span className="block-level-badge">Recommended</span> : null}
              </span>
              <span className="block-level-help">{level.summary}</span>
            </label>
          )
        })}
      </div>
      <p className="hint">{hint}</p>
      {error ? <Notice tone="error">{error}</Notice> : null}
    </div>
  )
}
