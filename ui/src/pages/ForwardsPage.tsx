// SPDX-License-Identifier: MIT

import { useCallback, useState } from 'react'

import type { Forward } from '../api'
import { AutoMapCard } from '../components/AutoMapCard'
import { ForwardDialog } from '../components/ForwardDialog'
import { ForwardsTable } from '../components/ForwardsTable'
import { Notice } from '../components/primitives'
import type { SettingsForm } from '../components/settings/useSettingsDraft'
import { usePolled, useStore } from '../data/StoreProvider'

type Overlay = { kind: 'none' } | { kind: 'add' } | { kind: 'edit'; forward: Forward }

/** Everything about ports: the rules this machine serves to the tailnet, and the ports it
 *  opens automatically for the devices on it. */
export function ForwardsPage({
  form,
  agentUnreachable,
}: {
  form: SettingsForm
  /** agentUnreachable suppresses this page's own failure notice while the shell is already
   *  saying the agent stopped, so one dead agent produces one explanation. */
  agentUnreachable: boolean
}) {
  const [overlay, setOverlay] = useState<Overlay>({ kind: 'none' })
  const store = useStore()

  const status = usePolled('status')
  const forwards = usePolled('forwards')
  const automap = usePolled('automap')
  const tunnels = usePolled('tunnels')

  const refreshAll = useCallback(() => store.refreshAll(), [store])
  const closeOverlay = useCallback(() => setOverlay({ kind: 'none' }), [])

  return (
    <>
      {forwards.error && forwards.data === undefined && !agentUnreachable ? (
        <Notice tone="error">{forwards.error}</Notice>
      ) : null}

      <div className="deck">
        <ForwardsTable
          forwards={forwards.data ?? []}
          tunnels={tunnels.data ?? []}
          nodeRunning={status.data?.running ?? false}
          onChanged={refreshAll}
          onAdd={() => setOverlay({ kind: 'add' })}
          onEdit={(forward) => setOverlay({ kind: 'edit', forward })}
          form={form}
        />
        {automap.data ? <AutoMapCard view={automap.data} onChanged={refreshAll} form={form} /> : null}
      </div>

      {overlay.kind === 'add' || overlay.kind === 'edit' ? (
        <ForwardDialog
          editing={overlay.kind === 'edit' ? overlay.forward : undefined}
          onClose={closeOverlay}
          onSaved={refreshAll}
        />
      ) : null}
    </>
  )
}
