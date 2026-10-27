// SPDX-License-Identifier: MIT

import type { Access } from '../auth'
import { Panel } from './Panel'
import { Notice } from './primitives'

/**
 * SignedOut is the whole page while the agent will not talk to it. It replaces the frame
 * rather than sitting inside it: every section would only be another refused request, and
 * the one thing that helps is opening the dashboard again the way that signs it in.
 */
export function SignedOut({ access }: { access: Exclude<Access, { state: 'open' }> }) {
  if (access.state === 'no-storage') {
    return (
      <main className="content narrow">
        <Panel title="This browser will not keep the sign-in" primary>
          <p>
            app-tail keeps the dashboard signed in by storing a session in this browser, and
            the browser refused to store it. Private windows and strict privacy settings do
            this.
          </p>
          <p>
            Allow site data for this address, or use an ordinary window, then open the
            dashboard again from the app-tail menu or with <code>app-tail dashboard</code>.
          </p>
          <Notice tone="error">{access.reason}</Notice>
        </Panel>
      </main>
    )
  }
  return (
    <main className="content narrow">
      <Panel title="Open the dashboard again" primary>
        <p>This page is not signed in to app-tail, so it cannot show or change anything.</p>
        <p>
          Open the dashboard from the app-tail menu in the menu bar or system tray, or run{' '}
          <code>app-tail dashboard</code> in a terminal. Either one signs this browser in again.
        </p>
        <Notice tone="warn">{access.reason}</Notice>
      </Panel>
    </main>
  )
}
