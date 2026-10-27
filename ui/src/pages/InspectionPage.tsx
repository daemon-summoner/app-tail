// SPDX-License-Identifier: MIT

// What this app looks at in the traffic it carries, and what it does about what it finds.
//
// Its own page rather than a card under Settings: the inspection engine has more settings
// than the rest of Security together, and the level it runs at is one of the four things
// the dashboard is opened to change.

import { ApprovalBanner } from '../components/ApprovalBanner'
import { IpsCard } from '../components/IpsCard'
import type { SettingsForm } from '../components/settings/useSettingsDraft'
import { usePolled, useStore } from '../data/StoreProvider'

export function InspectionPage({ form }: { form: SettingsForm }) {
  const ips = usePolled('ips')
  const status = usePolled('status')
  const store = useStore()
  return (
    <div className="deck">
      <ApprovalBanner
        approvals={status.data?.approvals}
        feature="tls-interception"
        onApproved={() => store.refreshAll()}
      />
      {ips.data ? <IpsCard view={ips.data} form={form} onChanged={ips.refresh} /> : null}
    </div>
  )
}
