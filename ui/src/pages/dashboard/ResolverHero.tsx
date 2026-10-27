// SPDX-License-Identifier: MIT

// Which resolver every program on this machine uses, as a dashboard card.
//
// The picker is the one the DNS page carries. It is here because it is the other switch
// somebody flips repeatedly, and its head says what is in force rather than what was
// chosen: the override is installed by the machine and the machine can refuse, and a card
// that only echoed the setting would never show that.

import type { DNSSystemView } from '../../api'
import { DnsProfilePicker, useDnsProfiles } from '../../components/pickers/DnsProfilePicker'
import type { SettingsForm } from '../../components/settings/useSettingsDraft'
import { HeroCard } from './HeroCard'
import { heroNamed } from './heroes'

const HERO = heroNamed('resolver')

/** The resolver's state as one word, for the head of its card. */
function dnsStatus(view: DNSSystemView | undefined): {
  tone: string
  label: string
  detail?: string
} {
  if (view === undefined) return { tone: 'pending', label: 'reading' }
  if (!view.enabled) return { tone: 'off', label: 'unchanged' }
  if (!view.applied) return { tone: 'error', label: 'not in force' }
  return { tone: 'running', label: 'in force', detail: view.profileLabel ?? view.profile }
}

export function ResolverHero({ form, view }: { form: SettingsForm; view: DNSSystemView | undefined }) {
  const { profiles, error } = useDnsProfiles()

  return (
    <HeroCard
      hero={HERO}
      info={
        <p>
          The resolver every program on this machine uses. app-tail puts your previous settings
          back when you choose System default.
        </p>
      }
      status={dnsStatus(view)}
    >
      {view === undefined ? (
        <p className="hint">This agent does not carry the machine-wide resolver.</p>
      ) : (
        <DnsProfilePicker view={view} form={form} profiles={profiles} error={error} />
      )}
    </HeroCard>
  )
}
