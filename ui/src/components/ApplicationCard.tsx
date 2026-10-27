// SPDX-License-Identifier: MIT

// How app-tail itself behaves on this machine, and the facts about this install.
//
// The About settings are read-only, so they render as a fact list beside the controls
// rather than as a section of their own: three lines nobody can change do not need a
// heading, but they do need to be somewhere.

import { Panel } from './Panel'
import { CardSettings } from './settings/CardSettings'
import { fieldsInGroup } from './settings/fieldState'
import type { SettingsForm } from './settings/useSettingsDraft'

const APP_GROUP = 'application'
const ABOUT_GROUP = 'about'

export function ApplicationCard({ form }: { form: SettingsForm }) {
  const facts = fieldsInGroup(form.available, ABOUT_GROUP, true)

  return (
    <Panel
      title="This app"
      wide
      id="application"
      info={
        <>
          <p>How app-tail itself behaves on this machine: its dashboard address, its
            tray icon, and whether it starts when you log in.</p>
          <p>
            The dashboard address and the tray icon are read when app-tail starts, so a
            change to either applies the next time it does; everything else here applies
            as soon as it is changed.
          </p>
        </>
      }
    >
      <CardSettings form={form} groups={[APP_GROUP]} />

      {facts.length > 0 ? (
        <dl className="proxy-counters app-facts">
          {facts.map((field) => (
            <div key={field.key}>
              <dt>{field.label}</dt>
              <dd className="mono">{String(form.bind(field).value) || '—'}</dd>
            </div>
          ))}
        </dl>
      ) : null}
    </Panel>
  )
}
