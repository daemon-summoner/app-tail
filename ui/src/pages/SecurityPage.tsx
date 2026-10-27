// SPDX-License-Identifier: MIT

import { LockCard } from '../components/LockCard'
import { PrefsCard } from '../components/PrefsCard'
import { SecurityCard } from '../components/SecurityCard'
import type { SettingsForm } from '../components/settings/useSettingsDraft'
import { usePolled } from '../data/StoreProvider'

/**
 * Security holds three cards rather than one: what this app does with its own dashboard,
 * what the tailnet's lock does to this device, and the node's own preferences. All three
 * are answers to "who can reach what", which is why they share a page. What the app does
 * with the traffic it carries has a section of its own, Inspection.
 *
 * What a page renders decides what the agent is polled for, so the three polls live here
 * and nowhere a reader on another page would pay for them.
 */
export function SecurityPage({ form }: { form: SettingsForm }) {
  const lock = usePolled('lock')
  const prefs = usePolled('prefs')
  const tunnels = usePolled('tunnels')
  return (
    <div className="deck">
      <SecurityCard form={form} tunnels={tunnels.data ?? []} />
      {prefs.data && (prefs.data.fields?.length ?? 0) > 0 ? <PrefsCard view={prefs.data} /> : null}
      {/* Lock has no switch of its own -- an administrator turns it on for the whole
          tailnet -- so unlike every other card here it appears only when it applies. */}
      {lock.data?.enabled ? <LockCard view={lock.data} onChanged={lock.refresh} /> : null}
    </div>
  )
}
