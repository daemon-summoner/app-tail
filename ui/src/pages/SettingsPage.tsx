// SPDX-License-Identifier: MIT

import { ApplicationCard } from '../components/ApplicationCard'
import type { SettingsForm } from '../components/settings/useSettingsDraft'
import { href, type SettingsSectionId } from '../lib/router'

/**
 * Settings holds what is about this app itself rather than about any one feature: where
 * its dashboard listens, its tray, its identity. Every feature's own settings live on that
 * feature's page.
 */
export function SettingsPage({
  section,
  form,
}: {
  section: SettingsSectionId | undefined
  form: SettingsForm
}) {
  switch (section) {
    case 'application':
      return (
        <div className="deck">
          <ApplicationCard form={form} />
        </div>
      )
    default:
      return <NoSuchSection />
  }
}

/** A stale link is the usual way someone gets here, so it says where they are and offers
 *  the way back rather than quietly showing a different page. */
function NoSuchSection() {
  return (
    <section className="panel" aria-label="No such section">
      <div className="panel-body">
        <p>That settings section is not part of this dashboard.</p>
        <p>
          <a href={href('settings', 'application')}>Open the app&rsquo;s own settings</a>
        </p>
      </div>
    </section>
  )
}
