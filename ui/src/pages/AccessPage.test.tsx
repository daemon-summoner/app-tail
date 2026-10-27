// SPDX-License-Identifier: MIT

import { act, fireEvent, within } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'

import { AccessPage } from './AccessPage'
import {
  emptySettingsForm,
  failWith,
  makeProxyInstance,
  noContent,
  proxyRoutes,
  rejectField,
  renderAgent,
  settingsFormWithModules,
  settle,
  tunnelRoutes,
  type AgentCall,
  type Routes,
} from '../test/agent'
import type { SettingsForm } from '../components/settings/useSettingsDraft'
import type { ProxyInstanceView } from '../api'

/** at renders the section at one address, which is the whole input this page takes. The
 *  form is the installation's, because one switch governs every proxy and no instance's own
 *  form can carry it. */
function at(
  params: readonly string[],
  routes: Routes = {},
  form: SettingsForm = settingsFormWithModules('proxy'),
) {
  return renderAgent(<AccessPage params={params} form={form} />, {
    ...tunnelRoutes(),
    ...proxyRoutes(),
    ...routes,
  })
}

/** add opens the dialog and submits a name through it, scoped to the dialog: every instance
 *  card on the page carries a Name field of its own, and the button that opens the dialog
 *  reads the same as the one that submits it. */
function add(view: Awaited<ReturnType<typeof at>>, name: string) {
  fireEvent.click(view.getByRole('button', { name: 'Add proxy' }))
  const dialog = within(view.getByRole('dialog', { name: 'Add a proxy' }))
  fireEvent.change(dialog.getByLabelText('Name'), { target: { value: name } })
  fireEvent.click(dialog.getByRole('button', { name: 'Add proxy' }))
}

/** A narrow instance: one program, one service, one connection. It is not the instance the
 *  command line reaches, so the agent serves it neither the auto-configuration script nor
 *  the ways of pointing a program at a proxy that go back through app-tail itself. */
const PSQL: ProxyInstanceView = makeProxyInstance({
  id: 'px_psql',
  name: 'psql',
  slug: 'psql',
  rules: [
    {
      id: 'ar_db',
      action: 'allow',
      tunnel: 'tn_primary',
      host: 'db.corp.internal',
      ports: ['5432'],
      protocol: 'tcp',
    },
  ],
  reach: ['allows port 5432 on db.corp.internal, over Tailnet'],
  listening: '127.0.0.1:1081',
  configuredAddr: '127.0.0.1:1081',
  socksUrl: 'socks5h://127.0.0.1:1081',
  httpUrl: 'http://127.0.0.1:1081',
})

describe('which page the address names', () => {
  // The rail links at the section itself, so arriving with nothing after it has to land
  // somewhere -- and the sentences are the page somebody who reads nothing else needs.
  it('shows what can reach what when the address names no page', async () => {
    const view = await at([])

    expect(view.getByRole('region', { name: 'What can reach what' })).toBeInTheDocument()
  })

  // A stale link is the usual way somebody gets here. Quietly showing the first page would
  // leave a bookmark that goes somewhere else with nothing saying so.
  it('says so when the address names no access page', async () => {
    const view = await at(['nonesuch'])

    expect(view.getByRole('region', { name: 'No such section' })).toBeInTheDocument()
  })
})

describe('what can reach what', () => {
  // The sentences are the agent's, in the agent's order: the first rule that fits a
  // destination decides it, so a list reordered on the way here would describe a different
  // proxy from the one that is running.
  it('lists what each proxy reaches, in the order the rules are matched', async () => {
    const view = await at(
      ['grants'],
      proxyRoutes([
        makeProxyInstance({
          reach: ['refuses port 22 anywhere', 'allows any port anywhere, over Tailnet'],
        }),
      ]),
    )

    const sentences = view.container.querySelectorAll('.grant-list li')
    expect([...sentences].map((li) => li.textContent)).toEqual([
      'refuses port 22 anywhere',
      'allows any port anywhere, over Tailnet',
    ])
  })

  it('leads from a proxy to the rules that decide what it reaches', async () => {
    const view = await at(['grants'], proxyRoutes([PSQL]))

    expect(view.getByRole('link', { name: 'Change what it reaches' })).toHaveAttribute(
      'href',
      '#/connections/rules/px_psql',
    )
  })

  // Nothing set up is a state, not a fault. A blank page here reads as one that failed to
  // load, and leaves somebody with no idea what a proxy even is.
  it('says how to start when no proxy is set up', async () => {
    const view = await at(['grants'], proxyRoutes([]))

    expect(view.getByText(/There are no proxies set up here yet/)).toBeInTheDocument()
    expect(view.getByRole('link', { name: 'Add one' })).toHaveAttribute('href', '#/connections/proxies')
  })
})

describe('the proxies', () => {
  it('shows where a program is pointed at each one', async () => {
    const view = await at(['proxies'], proxyRoutes([PSQL]))

    expect(view.getByText('socks5h://127.0.0.1:1081')).toBeInTheDocument()
    expect(view.getByText('http://127.0.0.1:1081')).toBeInTheDocument()
  })

  // The commands are rendered by the agent, and which of them apply differs per instance:
  // the ways that go back through app-tail itself address the one proxy the command line
  // reaches. Showing them on a narrow instance's card would tell somebody to run a command
  // that gives their program the default proxy's permissions instead of this one's.
  it('offers the ways of pointing a program at the proxy the card is about', async () => {
    const view = await at(['proxies'], proxyRoutes([makeProxyInstance(), PSQL]))

    expect(view.getByText('app-tail exec -- curl http://peer.your-tailnet.ts.net:8080/')).toBeInTheDocument()
    expect(
      view.getByText('curl --socks5-hostname 127.0.0.1:1081 http://peer:8080/'),
    ).toBeInTheDocument()
    // One instance offers the app-mediated way; the narrow one offers curl only, so two
    // cards carry three commands between them rather than four.
    expect(view.container.querySelectorAll('.snippet').length).toBe(3)
  })

  // The auto-configuration address is a way of pointing a browser at a proxy, so it belongs
  // beside the other addresses -- and only on the instance the served script answers for.
  it('publishes the auto-configuration address only where there is one', async () => {
    const view = await at(['proxies'], proxyRoutes([makeProxyInstance(), PSQL]))

    expect(view.getByText('http://127.0.0.1:8377/proxy.pac')).toBeInTheDocument()
    expect(view.getAllByText('Auto-config').length).toBe(1)
  })

  // Off is a state, not a fault: every instance keeps its settings and its rules, and the
  // switch that runs them is not on this page. Painting them as broken here would send
  // somebody looking for a failure that is not there.
  it('reports every proxy as off when the switch that runs them is off', async () => {
    const view = await at(['proxies'], {}, emptySettingsForm())

    expect(view.getByText(/none of them is listening/)).toBeInTheDocument()
  })

  it('adds a proxy and goes straight to granting it something', async () => {
    const view = await at(['proxies'], {
      'POST /api/proxies': makeProxyInstance({ id: 'px_psql', name: 'psql', slug: 'psql' }),
    })

    add(view, 'psql')
    await settle()

    expect(view.agent.bodyOf('POST /api/proxies')).toEqual({ name: 'psql' })
    // It was added reaching nothing, and granting it something is the only thing that makes
    // it useful.
    expect(window.location.hash).toBe('#/connections/rules/px_psql')
  })

  // A refusal is the reader's to fix, so it stays on the form with the reason on it. A
  // dialog that closed would read as a proxy that was added.
  it('keeps the add form open with the reason when the agent refuses', async () => {
    const view = await at(['proxies'], {
      'POST /api/proxies': failWith(400, '127.0.0.1:1080 is already asked for by "Default"'),
    })

    add(view, 'psql')
    await settle()

    expect(view.getByRole('dialog', { name: 'Add a proxy' })).toBeInTheDocument()
    expect(
      view.getByText('127.0.0.1:1080 is already asked for by "Default"'),
    ).toBeInTheDocument()
  })

  // The one instance every install has is where this installation's own proxy settings are
  // applied, so the agent refuses to remove it. Offering the button anyway would put a
  // control on screen whose only outcome is a refusal.
  it('offers no way to remove a proxy the agent will not remove', async () => {
    const view = await at(['proxies'])

    expect(view.queryByRole('button', { name: 'Remove' })).not.toBeInTheDocument()
  })

  it('asks before removing a proxy, and removes it once answered', async () => {
    const view = await at(['proxies'], {
      ...proxyRoutes([PSQL]),
      'DELETE /api/proxies/px_psql': noContent(),
    })

    fireEvent.click(view.getByRole('button', { name: 'Remove' }))
    expect(view.agent.countOf('DELETE /api/proxies/px_psql')).toBe(0)

    fireEvent.click(view.getByRole('button', { name: 'Remove proxy' }))
    await settle()

    expect(view.agent.countOf('DELETE /api/proxies/px_psql')).toBe(1)
  })

  it('reports why a removal was refused', async () => {
    const view = await at(['proxies'], {
      ...proxyRoutes([PSQL]),
      'DELETE /api/proxies/px_psql': failWith(400, 'the default proxy cannot be removed'),
    })

    fireEvent.click(view.getByRole('button', { name: 'Remove' }))
    fireEvent.click(view.getByRole('button', { name: 'Remove proxy' }))
    await settle()

    expect(view.getByText('the default proxy cannot be removed')).toBeInTheDocument()
  })

  // The instance's form is the shared draft machinery pointed at the instance endpoints,
  // so what is proven here is the pointing: the edit reaches this instance's own address
  // with only the key that changed, and the card above the form follows the answer rather
  // than waiting a poll for the rename to appear.
  it('writes an edited setting to the instance it belongs to, and reads it back', async () => {
    const renamed = makeProxyInstance({ ...PSQL, name: 'postgres', slug: 'psql' })
    const view = await at(['proxies'], {
      ...proxyRoutes([PSQL]),
      'PUT /api/proxies/px_psql': (call: AgentCall) => {
        view.agent.set('GET /api/proxies', { proxies: [renamed] })
        return { ...renamed, settings: { ...renamed.settings, ...JSON.parse(call.body ?? '{}') } }
      },
    })

    fireEvent.click(view.getByText(/psql settings/))
    fireEvent.change(view.getByLabelText('Name'), { target: { value: 'postgres' } })
    await settle()
    expect(view.agent.countOf('PUT /api/proxies')).toBe(0)

    fireEvent.click(view.getByRole('button', { name: 'Save' }))
    await settle()

    expect(view.agent.bodyOf('PUT /api/proxies/px_psql')).toEqual({ name: 'postgres' })
    expect(view.getByRole('region', { name: 'postgres' })).toBeInTheDocument()
    expect(view.getByLabelText('Name')).toHaveValue('postgres')
  })

  it('keeps a refused edit on the form with the reason, and writes nothing else', async () => {
    const view = await at(['proxies'], {
      ...proxyRoutes([PSQL]),
      'PUT /api/proxies/px_psql': rejectField('name', 'a proxy named "Default" already exists'),
    })

    fireEvent.click(view.getByText(/psql settings/))
    fireEvent.change(view.getByLabelText('Name'), { target: { value: 'Default' } })
    fireEvent.click(view.getByRole('button', { name: 'Save' }))
    await settle()

    expect(view.getByLabelText('Name')).toHaveValue('Default')
    expect(view.getByLabelText('Name')).toBeInvalid()
    expect(view.container.querySelector('.field-error')).toHaveTextContent(
      'a proxy named "Default" already exists',
    )
    expect(view.getByRole('region', { name: 'psql' })).toBeInTheDocument()
    expect(view.agent.countOf('PUT /api/proxies')).toBe(1)
  })
})

describe('asking what a proxy would do', () => {
  // The whole point of the tester: rule order is the difficulty of this model, and an
  // answer that does not name the line that decided leaves somebody editing rules and
  // guessing which one they are changing.
  it('names the rule that decided', async () => {
    const view = await at(['proxies'], {
      ...proxyRoutes([PSQL]),
      'POST /api/proxies/px_psql/test': {
        address: 'db.corp.internal:5432',
        allowed: true,
        resolved: '10.0.0.5:5432',
        tunnel: 'tn_primary',
        tunnelName: 'Tailnet',
        rule: 'ar_db',
        ruleIndex: 1,
        reason: 'rule 1 allows port 5432 on Tailnet',
      },
    })

    fireEvent.change(view.getByLabelText('Can psql reach'), {
      target: { value: 'db.corp.internal:5432' },
    })
    fireEvent.click(view.getByRole('button', { name: 'Ask' }))
    await settle()

    expect(view.agent.bodyOf('POST /api/proxies/px_psql/test')).toEqual({
      address: 'db.corp.internal:5432',
      protocol: 'tcp',
    })
    expect(view.getByText('rule 1 (ar_db)')).toBeInTheDocument()
    expect(view.getByText('10.0.0.5:5432')).toBeInTheDocument()
  })

  // A refusal is the model working. Colouring it as a fault would make a correctly narrow
  // grant read as broken every time somebody checked it -- and is how people stop believing
  // the colour that means something is actually wrong.
  it('reports a refusal as an answer rather than as a fault', async () => {
    const view = await at(['proxies'], {
      ...proxyRoutes([PSQL]),
      'POST /api/proxies/px_psql/test': {
        address: '10.0.0.5:22',
        allowed: false,
        reason: 'no rule allows it, so it is refused',
      },
    })

    fireEvent.change(view.getByLabelText('Can psql reach'), { target: { value: '10.0.0.5:22' } })
    fireEvent.click(view.getByRole('button', { name: 'Ask' }))
    await settle()

    expect(view.container.querySelector('.notice.error')).toBeNull()
    expect(
      view.getByText('no rule — anything no rule allows is refused'),
    ).toBeInTheDocument()
  })
})

describe('the rules', () => {
  // Rules belong to one proxy, so arriving without naming one is a question rather than an
  // error page.
  it('asks which proxy when the address names none', async () => {
    const view = await at(['rules'], proxyRoutes([PSQL]))

    expect(view.getByRole('link', { name: 'psql' })).toHaveAttribute(
      'href',
      '#/connections/rules/px_psql',
    )
  })

  it('says so when the address names no proxy', async () => {
    const view = await at(['rules', 'px_absent'])

    expect(view.getByRole('region', { name: 'No such proxy' })).toBeInTheDocument()
  })

  it('draws a numbered row per rule, in the order they are matched', async () => {
    const view = await at(['rules', 'px_psql'], proxyRoutes([PSQL]))

    expect(view.getByRole('region', { name: 'What psql may reach' })).toBeInTheDocument()
    expect(view.getByLabelText('Rule 1: destination')).toHaveValue('db.corp.internal')
    expect(view.getByLabelText('Rule 1: ports')).toHaveValue('5432')
  })

  it('writes the whole ordered list back when a rule is changed', async () => {
    const view = await at(['rules', 'px_psql'], {
      ...proxyRoutes([PSQL]),
      'PUT /api/proxies/px_psql/rules': PSQL,
    })

    fireEvent.change(view.getByLabelText('Rule 1: ports'), { target: { value: '5432,5433' } })
    fireEvent.click(view.getByRole('button', { name: 'Save rules' }))
    await settle()

    expect(view.agent.bodyOf('PUT /api/proxies/px_psql/rules')).toEqual({
      rules: [
        {
          id: 'ar_db',
          action: 'allow',
          tunnel: 'tn_primary',
          host: 'db.corp.internal',
          ports: ['5432', '5433'],
          protocol: 'tcp',
        },
      ],
    })
  })

  // Order is the meaning: the first rule that fits decides, so a deny written below the
  // grant it carves an exception out of never runs. Moving a row has to be what is saved.
  it('saves the new order when a rule is moved', async () => {
    const twoRules = makeProxyInstance({
      id: 'px_psql',
      name: 'psql',
      rules: [
        { id: 'ar_allow', action: 'allow', tunnel: 'tn_primary' },
        { id: 'ar_deny', action: 'deny', tunnel: 'tn_primary', ports: ['22'] },
      ],
    })
    const view = await at(['rules', 'px_psql'], {
      ...proxyRoutes([twoRules]),
      'PUT /api/proxies/px_psql/rules': twoRules,
    })

    fireEvent.click(view.getByRole('button', { name: 'Move rule 2 up' }))
    fireEvent.click(view.getByRole('button', { name: 'Save rules' }))
    await settle()

    const sent: { rules: { id: string }[] } = view.agent.bodyOf('PUT /api/proxies/px_psql/rules')
    expect(sent.rules.map((r) => r.id)).toEqual(['ar_deny', 'ar_allow'])
  })

  // Nothing to save is not the same as saving nothing. A live Save button on an untouched
  // list invites a write that cannot do anything, and hides whether an edit registered.
  it('offers nothing to save until a rule is edited', async () => {
    const view = await at(['rules', 'px_psql'], proxyRoutes([PSQL]))

    expect(view.getByRole('button', { name: 'Save rules' })).toBeDisabled()

    fireEvent.change(view.getByLabelText('Rule 1: ports'), { target: { value: '5432,5433' } })

    expect(view.getByRole('button', { name: 'Save rules' })).toBeEnabled()
  })

  // A refused list leaves the instance with the permissions it had, so the rows stay on
  // screen with the reason. Clearing them would look like a save that emptied the list.
  it('keeps the edited rows on screen with the reason a write was refused', async () => {
    const view = await at(['rules', 'px_psql'], {
      ...proxyRoutes([PSQL]),
      'PUT /api/proxies/px_psql/rules': failWith(
        400,
        'rule 1 names connection "tn_absent", which is not configured',
      ),
    })

    fireEvent.change(view.getByLabelText('Rule 1: ports'), { target: { value: '5432,5433' } })
    fireEvent.click(view.getByRole('button', { name: 'Save rules' }))
    await settle()

    expect(
      view.getByText('rule 1 names connection "tn_absent", which is not configured'),
    ).toBeInTheDocument()
    expect(view.getByLabelText('Rule 1: ports')).toHaveValue('5432,5433')
  })

  // An instance with nothing granted reaches nothing, and says so: an empty table would
  // read as rules that failed to load rather than as the safe state a new proxy is in.
  it('says a proxy with no rules reaches nothing', async () => {
    const view = await at(
      ['rules', 'px_psql'],
      proxyRoutes([makeProxyInstance({ id: 'px_psql', name: 'psql', rules: [], reach: [] })]),
    )

    expect(view.getByText(/This proxy reaches nothing/)).toBeInTheDocument()
  })

  // A new row is a grant that reaches anything, on every port, over any transport, on any
  // connection: the agent mints its id, and the table has to take that id back so the next
  // save does not present the same rule as new a second time.
  it('adds a blank grant, and keeps the id the agent mints for it', async () => {
    const minted = makeProxyInstance({
      id: 'px_psql',
      name: 'psql',
      rules: [...PSQL.rules, { id: 'ar_new', action: 'allow', tunnel: 'tn_primary' }],
    })
    const view = await at(['rules', 'px_psql'], {
      ...proxyRoutes([PSQL]),
      'PUT /api/proxies/px_psql/rules': minted,
    })

    fireEvent.click(view.getByRole('button', { name: 'Add a rule' }))

    expect(view.getByLabelText('Rule 2: allow or deny')).toHaveValue('allow')
    expect(view.getByLabelText('Rule 2: destination')).toHaveValue('')
    expect(view.getByText(/^anywhere/)).toBeInTheDocument()

    fireEvent.click(view.getByRole('button', { name: 'Save rules' }))
    await settle()

    const sent: { rules: { id: string; action: string; tunnel?: string }[] } =
      view.agent.bodyOf('PUT /api/proxies/px_psql/rules')
    expect(sent.rules[1]).toEqual({ id: '', action: 'allow' })

    fireEvent.change(view.getByLabelText('Rule 2: ports'), { target: { value: '443' } })
    fireEvent.click(view.getByRole('button', { name: 'Save rules' }))
    await settle()

    const again: { rules: { id: string }[] } = view.agent.bodyOf(
      'PUT /api/proxies/px_psql/rules',
      1,
    )
    expect(again.rules.map((r) => r.id)).toEqual(['ar_db', 'ar_new'])
  })

  it('writes an empty list when the last rule is removed', async () => {
    const view = await at(['rules', 'px_psql'], {
      ...proxyRoutes([PSQL]),
      'PUT /api/proxies/px_psql/rules': makeProxyInstance({ id: 'px_psql', rules: [] }),
    })

    fireEvent.click(view.getByRole('button', { name: 'Remove rule 1' }))
    expect(view.getByText(/This proxy reaches nothing/)).toBeInTheDocument()

    fireEvent.click(view.getByRole('button', { name: 'Save rules' }))
    await settle()

    expect(view.agent.bodyOf('PUT /api/proxies/px_psql/rules')).toEqual({ rules: [] })
  })

  it('puts the rows back as they were when the edits are discarded', async () => {
    const view = await at(['rules', 'px_psql'], proxyRoutes([PSQL]))

    fireEvent.change(view.getByLabelText('Rule 1: ports'), { target: { value: '5432,5433' } })
    fireEvent.click(view.getByRole('button', { name: 'Add a rule' }))
    expect(view.getByText('Unsaved changes')).toBeInTheDocument()

    fireEvent.click(view.getByRole('button', { name: 'Discard' }))

    expect(view.getByLabelText('Rule 1: ports')).toHaveValue('5432')
    expect(view.queryByLabelText('Rule 2: destination')).not.toBeInTheDocument()
    expect(view.queryByText('Unsaved changes')).not.toBeInTheDocument()
    expect(view.getByRole('button', { name: 'Save rules' })).toBeDisabled()
    expect(view.agent.countOf('PUT /api/proxies/px_psql/rules')).toBe(0)
  })

  // The first row cannot go up and the last cannot go down; a click that did nothing
  // would still mark the list edited and offer a save of the same order.
  it('offers no move off either end of the list', async () => {
    const view = await at(['rules', 'px_psql'], proxyRoutes([PSQL]))

    expect(view.getByRole('button', { name: 'Move rule 1 up' })).toBeDisabled()
    expect(view.getByRole('button', { name: 'Move rule 1 down' })).toBeDisabled()
  })

  // A rule may carry both a name and the range that name has to resolve inside. The box
  // shows the name, so the range is said beside it and carried through a save untouched;
  // dropping it would quietly widen the rule to wherever the name resolves.
  it('carries the range beside a name through a save rather than dropping it', async () => {
    const narrowed = makeProxyInstance({
      id: 'px_psql',
      name: 'psql',
      rules: [
        {
          id: 'ar_db',
          action: 'allow',
          tunnel: 'tn_primary',
          host: 'db.corp.internal',
          cidr: '10.0.0.0/8',
          ports: ['5432'],
        },
      ],
    })
    const view = await at(['rules', 'px_psql'], {
      ...proxyRoutes([narrowed]),
      'PUT /api/proxies/px_psql/rules': narrowed,
    })

    expect(view.getByLabelText('Rule 1: destination')).toHaveValue('db.corp.internal')
    expect(view.getByText(/only when that resolves inside 10.0.0.0\/8/)).toBeInTheDocument()

    fireEvent.change(view.getByLabelText('Rule 1: note'), { target: { value: 'the DB' } })
    fireEvent.click(view.getByRole('button', { name: 'Save rules' }))
    await settle()

    const sent: { rules: { host?: string; cidr?: string; note?: string }[] } =
      view.agent.bodyOf('PUT /api/proxies/px_psql/rules')
    expect(sent.rules[0]).toMatchObject({
      host: 'db.corp.internal',
      cidr: '10.0.0.0/8',
      note: 'the DB',
    })
  })

  // Retyping the name as a range makes it a range: the carried CIDR belongs to the name,
  // not to whatever the box holds now.
  it('drops the carried range once the destination is written as a range itself', async () => {
    const narrowed = makeProxyInstance({
      id: 'px_psql',
      name: 'psql',
      rules: [
        { id: 'ar_db', action: 'allow', tunnel: 'tn_primary', host: 'db.corp.internal', cidr: '10.0.0.0/8' },
      ],
    })
    const view = await at(['rules', 'px_psql'], {
      ...proxyRoutes([narrowed]),
      'PUT /api/proxies/px_psql/rules': narrowed,
    })

    fireEvent.change(view.getByLabelText('Rule 1: destination'), {
      target: { value: '10.1.0.0/16' },
    })
    fireEvent.click(view.getByRole('button', { name: 'Save rules' }))
    await settle()

    const sent: { rules: { host?: string; cidr?: string }[] } = view.agent.bodyOf(
      'PUT /api/proxies/px_psql/rules',
    )
    expect(sent.rules[0]).toEqual({
      id: 'ar_db',
      action: 'allow',
      tunnel: 'tn_primary',
      cidr: '10.1.0.0/16',
    })
  })

  // The instance is polled, so its rules can change under the table -- another window,
  // the command line. An untouched table takes the new list; one being edited keeps what
  // is being typed, because a poll that threw that away would be worse than a stale list.
  it('follows a change made elsewhere only while nothing is being edited here', async () => {
    vi.useFakeTimers()
    try {
      const view = await at(['rules', 'px_psql'], proxyRoutes([PSQL]))
      const widened = makeProxyInstance({
        id: 'px_psql',
        name: 'psql',
        rules: [{ ...PSQL.rules[0]!, ports: ['5432', '5433'] }],
      })
      view.agent.set('GET /api/proxies', { proxies: [widened] })

      await act(async () => {
        await vi.advanceTimersByTimeAsync(4000)
      })
      await settle()
      expect(view.getByLabelText('Rule 1: ports')).toHaveValue('5432, 5433')

      fireEvent.change(view.getByLabelText('Rule 1: note'), { target: { value: 'typing' } })
      view.agent.set('GET /api/proxies', {
        proxies: [makeProxyInstance({ id: 'px_psql', name: 'psql', rules: [] })],
      })
      await act(async () => {
        await vi.advanceTimersByTimeAsync(4000)
      })
      await settle()

      expect(view.getByLabelText('Rule 1: note')).toHaveValue('typing')
      expect(view.getByLabelText('Rule 1: ports')).toHaveValue('5432, 5433')
    } finally {
      vi.useRealTimers()
    }
  })

  it('says a rule cannot be written when the words it may use could not be read', async () => {
    const view = await at(['rules', 'px_psql'], {
      ...proxyRoutes([PSQL]),
      'GET /api/proxies/schema': failWith(500, 'the schema could not be built'),
    })

    expect(view.getByText(/Could not read what a rule may say/)).toHaveTextContent(
      'the schema could not be built',
    )
  })

  it('says there is nothing to write rules for when no proxy is set up', async () => {
    const view = await at(['rules'], proxyRoutes([]))

    expect(view.getByText(/there are none set up here yet/)).toBeInTheDocument()
    expect(view.getByRole('link', { name: 'Add one' })).toHaveAttribute(
      'href',
      '#/connections/proxies',
    )
  })
})
