// SPDX-License-Identifier: MIT

// Where this machine's internet traffic leaves through, as a picker of destinations.
//
// The rows are this machine's own network and every stored connection, which is what makes
// the control reversible: a picker offering only connections could move the traffic away
// and not back. The choices are read from the served schema, so this offers exactly the
// connections the agent would accept and exactly the ones the menu bar offers.

import { useState } from 'react'
import type { EgressView } from '../../api'
import { Notice } from '../primitives'
import type { SettingsForm } from '../settings/useSettingsDraft'
import { ChoicePicker, type Choice } from './ChoicePicker'

const MODE_KEY = 'egress.mode'
const TUNNEL_KEY = 'egress.tunnelId'

/** The two modes, mirroring config.EgressDirect and config.EgressTunnel. */
const DIRECT = 'direct'
const THROUGH_TUNNEL = 'tunnel'

/** DIRECT_ROW is the value standing for this machine's own network. The mode is what says
 *  it, and no connection id means it, so the row that means it holds no id. */
const DIRECT_ROW = ''

export function EgressPicker({ view, form }: { view: EgressView | undefined; form: SettingsForm }) {
  const [switching, setSwitching] = useState(false)

  const modeField = form.available.find((f) => f.key === MODE_KEY)
  const tunnelField = form.available.find((f) => f.key === TUNNEL_KEY)
  if (modeField === undefined || tunnelField === undefined) return null

  const directOption = (modeField.options ?? []).find((o) => o.value === DIRECT)
  const choices: Choice[] = [
    {
      value: DIRECT_ROW,
      label: directOption?.label ?? 'Out of this machine',
      detail: directOption?.help ?? '',
    },
    ...(tunnelField.options ?? []).map((option) => ({
      value: option.value,
      label: option.label,
      detail: option.help ?? '',
    })),
  ]

  // What is stored, not what is happening: this is the control, and whether the connection
  // it names is actually carrying the traffic is said beside it rather than by moving the
  // dot to a row nobody chose.
  const throughTunnel = String(form.bind(modeField).value ?? '') === THROUGH_TUNNEL
  const chosen = String(form.bind(tunnelField).value ?? '')
  const selected = throughTunnel ? chosen : DIRECT_ROW

  // Choosing a connection carries the mode with it: the connection is not read while the
  // mode says the traffic leaves this machine, so writing it alone would store a choice
  // that does nothing. Going back writes only the mode, which leaves the connection named
  // -- that remembered choice is what lets somebody switch back without picking again.
  const choose = async (value: string) => {
    if (value === selected) return
    setSwitching(true)
    try {
      await form.applyPatch(
        value === DIRECT_ROW
          ? { [MODE_KEY]: DIRECT }
          : { [MODE_KEY]: THROUGH_TUNNEL, [TUNNEL_KEY]: value },
      )
    } finally {
      setSwitching(false)
    }
  }

  const modeError = form.bind(modeField).error ?? form.bind(tunnelField).error

  return (
    <ChoicePicker
      legend="Internet traffic"
      name={MODE_KEY}
      choices={choices}
      selected={selected}
      disabled={switching || form.saving}
      loading="Loading connections…"
      empty="No connection is stored, so internet traffic leaves this machine."
      onChoose={(value) => void choose(value)}
    >
      {/* Said under the picker rather than in the head: the setting above is what somebody
          asked for, and this is the connection refusing to do it while the traffic keeps
          leaving this machine the way it always has. */}
      {throughTunnel && view !== undefined && !view.carrying && view.reason ? (
        <Notice tone="error">{view.reason}</Notice>
      ) : null}
      {modeError ? <Notice tone="error">{modeError}</Notice> : null}
    </ChoicePicker>
  )
}

/** What is happening, for the head beside the picker: the setting and the fact differ
 *  exactly when a chosen connection cannot carry the traffic, and that is the state worth
 *  a dot of its own. */
export function egressStatus(view: EgressView | undefined): {
  tone: string
  label: string
  detail?: string
} {
  if (view === undefined) return { tone: 'pending', label: 'reading' }
  if (view.mode !== THROUGH_TUNNEL) return { tone: 'off', label: 'leaving this machine' }
  if (view.carrying) {
    return { tone: 'running', label: 'carrying', detail: view.tunnelName ?? view.tunnelId ?? '' }
  }
  // Held and not-carrying are different outcomes: one stops the traffic here, the other
  // leaves it going out the way it always has.
  return { tone: 'error', label: view.held === true ? 'held' : 'not carrying' }
}
