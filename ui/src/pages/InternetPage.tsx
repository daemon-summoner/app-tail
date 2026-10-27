// SPDX-License-Identifier: MIT

// Where this machine's internet traffic leaves through, and the exceptions to it.
//
// It is about this machine rather than about one connection, which is why it is its own
// page and not on a connection's: the choice is which of the connections carries what
// none of them was asked for.

import { useCallback } from 'react'

import { EgressCard } from '../components/mode/EgressCard'
import { RoutingCard } from '../components/mode/RoutingCard'
import type { SettingsForm } from '../components/settings/useSettingsDraft'
import { usePolled, useStore } from '../data/StoreProvider'

export function InternetPage({ form }: { form: SettingsForm }) {
  const egress = usePolled('egress')
  const routing = usePolled('routing')
  const store = useStore()
  // A saved rule moves traffic, so what every other card is reporting -- what the
  // interface carries, which connections are being used -- is out of date the moment it
  // lands.
  const refreshAll = useCallback(() => store.refreshAll(), [store])

  return (
    <div className="deck">
      <EgressCard form={form} view={egress.data} error={egress.error} />

      {/* Directly under the card they except, because a rule is only readable next to
          the setting it overrides. */}
      <RoutingCard view={routing.data} error={routing.error} onSaved={refreshAll} />
    </div>
  )
}
