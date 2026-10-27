// SPDX-License-Identifier: MIT

// Which programs on this machine reach which of your networks, and how far into each:
// the last three pages under Connections.
//
// They sit under Connections rather than Settings for the reason the networks themselves
// do: what a reader comes here to find out is what is allowed, and the fields that decide
// it are the second question. Settings holds what the app does; this holds what it lets
// through.
//
// The three pages are ordered so a non-expert never has to open the third: the grants read
// as sentences, the proxies are the things a program is pointed at, and the rules table is
// last because rule order is semantics and nothing else on this page makes somebody learn
// that.

import { GrantsSection } from '../components/access/GrantsSection'
import { ProxiesSection } from '../components/access/ProxiesSection'
import { RulesSection } from '../components/access/RulesSection'
import type { SettingsForm } from '../components/settings/useSettingsDraft'
import { href, type ConnectionsSectionId } from '../lib/router'

/** The pages this component draws, which are the ones under Connections about access. */
const ACCESS_SECTIONS = ['grants', 'proxies', 'rules'] as const satisfies readonly ConnectionsSectionId[]

type AccessSectionId = (typeof ACCESS_SECTIONS)[number]

function isAccessSection(value: string): value is AccessSectionId {
  return (ACCESS_SECTIONS as readonly string[]).includes(value)
}

export function AccessPage({
  params,
  form,
}: {
  params: readonly string[]
  /** The installation's own settings, for the module switch every proxy is gated on. A
   *  proxy's own form cannot carry it: one switch governs every proxy. */
  form: SettingsForm
}) {
  const section = sectionOf(params)
  if (section === undefined) return <NoSuchSection />

  switch (section) {
    case 'grants':
      return <GrantsSection />
    case 'proxies':
      return <ProxiesSection form={form} />
    case 'rules':
      // The proxy whose rules these are, when the address names one. Rules belong to one
      // proxy, so the page asks which rather than picking one.
      return <RulesSection id={params[1]} />
  }
}

/** Which page the address names. An address with nothing after the section is the first
 *  page, which is what a reader arriving from the nav rail asks for; anything else that is
 *  not a page is a stale link and says so. */
function sectionOf(params: readonly string[]): AccessSectionId | undefined {
  const named = params[0]
  if (named === undefined) return 'grants'
  return isAccessSection(named) ? named : undefined
}

/** A stale link is the usual way someone gets here, so it says where they are and offers
 *  the way back rather than quietly showing a different page. */
function NoSuchSection() {
  return (
    <section className="panel" aria-label="No such section">
      <div className="panel-body">
        <p>That access section is not part of this dashboard.</p>
        <p>
          <a href={href('connections', 'grants')}>See what can reach what</a>
        </p>
      </div>
    </section>
  )
}
