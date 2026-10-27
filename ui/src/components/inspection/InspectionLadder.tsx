// SPDX-License-Identifier: MIT

// The inspection ladder: Off, Basic, Deep, Full, as one control.
//
// Each rung is a combination of the engine's switches, read back from the served view and
// written as a whole (see lib/inspectionLevel). Full is the one rung that changes something
// outside app-tail -- a root certificate this machine is asked to trust -- so it is not
// chosen by a click alone: the first time, the dialog says what that means and the person
// agrees, and the agreement is what the click writes alongside the switches.

import { useState } from 'react'

import { settingsSchema, type IPSView } from '../../api'
import {
  INSPECTION_RUNG_TEXT,
  INSPECTION_RUNGS,
  inspectionLevel,
  rungPatch,
  type InspectionRung,
} from '../../lib/inspectionLevel'
import { BlockLevels, type BlockLevel } from '../BlockLevels'
import { ConfirmDialog } from '../ConfirmDialog'
import { Notice } from '../primitives'
import type { SettingsForm } from '../settings/useSettingsDraft'

const AGREED_KEY = 'ips.interceptAgreed'
const FULL: InspectionRung = 'full'
const RECOMMENDED: InspectionRung = 'deep'

/** What agreeing means, in the words the setting itself carries, so the dialog and the
 *  advanced page cannot describe the same agreement two ways. */
const AGREEMENT = settingsSchema.find((f) => f.key === AGREED_KEY)?.help
if (AGREEMENT === undefined) {
  throw new Error(`the settings schema does not carry ${AGREED_KEY}`)
}

const LEVELS: readonly BlockLevel[] = INSPECTION_RUNGS.map((rung) => ({
  id: rung,
  ...INSPECTION_RUNG_TEXT[rung],
  recommended: rung === RECOMMENDED,
}))

interface InspectionLadderProps {
  view: IPSView
  form: SettingsForm
  /** Where the certificate commands are, for the line under Full that says the machine
   *  does not trust it yet. */
  advanced: string
  /** Called after a write lands, so the page's poll is re-read rather than waited for. */
  onChanged: () => void
}

export function InspectionLadder({ view, form, advanced, onChanged }: InspectionLadderProps) {
  const [asking, setAsking] = useState(false)
  const [refused, setRefused] = useState<string | undefined>(undefined)
  const level = inspectionLevel(view)

  // A refusal is thrown so the ladder shows it beneath the rungs, where the click was.
  // The form's own notice is at the top of the page.
  const write = async (patch: Record<string, unknown>) => {
    const outcome = await form.applyPatch(patch)
    if (!outcome.stored) throw new Error(outcome.reason)
    onChanged()
  }

  const choose = async (id: string) => {
    const rung = INSPECTION_RUNGS.find((r) => r === id)
    if (rung === undefined) throw new Error(`no inspection level is called ${id}`)
    if (rung === FULL && !view.intercept.agreed) {
      setAsking(true)
      return
    }
    await write(rungPatch(rung))
  }

  // The dialog stays open on a refusal, with the reason in it: closing it would read as
  // the agreement having been taken.
  const agree = () => {
    setRefused(undefined)
    void write({ ...rungPatch(FULL), [AGREED_KEY]: true }).then(
      () => setAsking(false),
      (cause: unknown) => setRefused(cause instanceof Error ? cause.message : String(cause)),
    )
  }

  const ask = () => {
    setRefused(undefined)
    setAsking(true)
  }

  return (
    <>
      <BlockLevels
        title="Inspection level"
        levels={LEVELS}
        chosen={level === 'custom' ? undefined : level}
        choose={choose}
        busy={form.saving || !form.loaded}
        hint={
          level === 'custom'
            ? 'The switches are set to a combination that is none of these levels. Choosing one replaces it; the feeds and your own entries are left alone.'
            : 'A level sets every inspection switch at once. The feeds and your own entries are left alone.'
        }
      />
      {level === FULL ? <FullStatus view={view} advanced={advanced} onAgree={ask} /> : null}
      {asking ? (
        <ConfirmDialog
          title="Open encrypted connections?"
          confirmLabel="I understand, open them"
          busy={form.saving}
          busyLabel="Saving…"
          onConfirm={agree}
          onClose={() => setAsking(false)}
        >
          <p>{AGREEMENT}</p>
          {refused ? <Notice tone="error">{refused}</Notice> : null}
        </ConfirmDialog>
      ) : null}
    </>
  )
}

/** The one line Full owes: whether connections are really being opened, and if not, which
 *  of the two things it waits on -- the agreement, or the certificate in the trust store.
 *  The agreement line carries the way to give it: Full is already the chosen rung here, and
 *  a chosen rung is not a thing to click again. */
function FullStatus({
  view,
  advanced,
  onAgree,
}: {
  view: IPSView
  advanced: string
  onAgree: () => void
}) {
  const held = view.intercept
  if (held.running && held.installed) {
    return (
      <p className="hint" data-intercept="running">
        Encrypted connections are being opened. {held.opened.toLocaleString()} opened so far.
      </p>
    )
  }
  if (!held.agreed) {
    return (
      <div className="hint notice-row" data-intercept="unagreed">
        <span>Nothing is opened until you confirm you understand what opening a connection does.</span>
        <button type="button" className="btn small" onClick={onAgree}>
          Read and confirm
        </button>
      </div>
    )
  }
  if (!held.installed) {
    return (
      <p className="hint" data-intercept="untrusted">
        This machine does not trust the certificate app-tail presents yet, so every connection
        it opens fails. <a href={advanced}>Install it</a> from the inspection page.
      </p>
    )
  }
  return (
    <p className="hint" data-intercept="waiting">
      Set to open encrypted connections, and nothing is being opened yet.
    </p>
  )
}
