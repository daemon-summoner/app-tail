// SPDX-License-Identifier: MIT

// Which resolver every program on this machine uses, as a picker that can stand on its
// own.
//
// It is the same control in two places: at the top of the dashboard, where choosing a
// resolver is one of the two things somebody opens this app to do, and on the resolver
// card, where it sits among everything else that feature knows. Both write the same pair
// of settings, so the switch is here rather than copied.

import { useCallback, useEffect, useState } from 'react'
import { api, type DNSProfile, type DNSSystemView } from '../../api'
import { Notice } from '../primitives'
import type { SettingsForm } from '../settings/useSettingsDraft'
import { ChoicePicker, type Choice } from './ChoicePicker'

/** SYSTEM_PROFILE is the profile that changes nothing. Choosing it is how the feature is
 *  turned off from the picker, so it is a value this control reasons about rather than
 *  just another row. It mirrors dnsprofiles.SystemID. */
export const SYSTEM_PROFILE = 'system'

/** TAILNET_PROFILE resolves through whatever nameservers the tailnet publishes, so it
 *  carries no servers of its own and the picker has to say where they come from instead of
 *  showing an empty list. It mirrors dnsprofiles.TailnetID. */
const TAILNET_PROFILE = 'tailnet'

/** The stored profiles, and a way to read them again. The list moves when somebody adds or
 *  edits one, and both the picker and the manager beside it are looking at it, so it is
 *  loaded once by whoever owns them rather than fetched separately by each. */
export function useDnsProfiles(): {
  profiles: DNSProfile[] | undefined
  error: string | undefined
  reload: () => void
} {
  const [profiles, setProfiles] = useState<DNSProfile[] | undefined>(undefined)
  const [error, setError] = useState<string | undefined>(undefined)

  const load = useCallback(
    (signal?: AbortSignal) =>
      api
        .dnsProfiles()
        .then((list) => {
          if (!signal?.aborted) setProfiles(list)
        })
        .catch((cause: unknown) => {
          if (!signal?.aborted) setError(cause instanceof Error ? cause.message : String(cause))
        }),
    [],
  )

  useEffect(() => {
    const ctrl = new AbortController()
    void load(ctrl.signal)
    return () => ctrl.abort()
  }, [load])

  return { profiles, error, reload: () => void load() }
}

/** One profile as a row of the picker: the name, and what it resolves through underneath.
 *  Two profiles named "Work" and "Home" are indistinguishable by name alone, and which
 *  resolver answers is the whole question this control exists for. */
export function serversLine(profile: DNSProfile): string {
  const servers = profile.servers ?? []
  if (servers.length > 0) return servers.join(', ')
  if (profile.id === TAILNET_PROFILE) {
    return 'Whatever nameservers your tailnet publishes, set in the Tailscale admin console.'
  }
  return "Leaves this machine's own resolver exactly as it is."
}

export function DnsProfilePicker({
  view,
  form,
  profiles,
  error,
}: {
  view: DNSSystemView
  form: SettingsForm
  profiles: DNSProfile[] | undefined
  /** What reading the list failed with, if it did. */
  error?: string | undefined
}) {
  const [switching, setSwitching] = useState(false)

  // The agent attributes a refused write to the setting it was about, and this is the
  // control that setting belongs to.
  const profileField = form.available.find((f) => f.key === 'systemDns.profile')
  const profileError = profileField ? form.bind(profileField).error : undefined

  // The switch travels with the profile, for the reason the menu and the CLI send it: the
  // profile is refused while the switch governing it is off, and System default means
  // "change nothing about this machine" rather than "stay on with a profile that has no
  // servers". Choosing System default writes the switch alone -- turning the module off
  // puts every setting it owns back to its default, so naming the profile there would name
  // a setting that same write has just made unavailable.
  const choose = async (id: string) => {
    const on = id !== SYSTEM_PROFILE
    if (id === view.profile && view.enabled === on) return
    setSwitching(true)
    try {
      await form.applyPatch({
        'systemDns.enabled': on,
        ...(on ? { 'systemDns.profile': id } : {}),
      })
    } finally {
      setSwitching(false)
    }
  }

  const choices: Choice[] | undefined = profiles?.map((profile) => ({
    value: profile.id,
    label: profile.name,
    detail: serversLine(profile),
  }))

  return (
    <ChoicePicker
      legend="Resolver"
      name="systemDns.profile"
      choices={choices}
      // A machine whose override is off resolves the way it always did, which is what the
      // System default row says, whatever profile is stored behind it.
      selected={view.enabled ? view.profile : SYSTEM_PROFILE}
      disabled={switching || form.saving}
      loading="Loading resolvers…"
      empty="No resolver profiles are stored."
      onChoose={(id) => void choose(id)}
    >
      {/* The refusal the agent attributed to this setting, under the control that
          caused it. The form's own error is already on the page once, above the
          cards, and printing it again here would read as two separate faults. */}
      {profileError ? <Notice tone="error">{profileError}</Notice> : null}
      {error ? <Notice tone="error">{error}</Notice> : null}
    </ChoicePicker>
  )
}
