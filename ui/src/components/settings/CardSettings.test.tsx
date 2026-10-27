// SPDX-License-Identifier: MIT

import { fireEvent, within } from '@testing-library/react'
import { describe, expect, it } from 'vitest'

import {
  makeSettings,
  makeSettingsResponse,
  makeSettingsSchema,
  renderAgent,
  settingsRoutes,
  settle,
} from '../../test/agent'
import { CardSettings, ModuleSwitch } from './CardSettings'
import { useSettingsDraft } from './useSettingsDraft'
import type { SettingsPatch } from '../../api'

/** A card's settings, driven by the same hook the dashboard uses. The write path is
 *  what these tests are about, so the form is real rather than stubbed. */
function Card({
  groups,
  omit,
  collapseLabel,
}: {
  groups: readonly string[]
  omit?: readonly string[]
  collapseLabel?: string
}) {
  const form = useSettingsDraft()
  return (
    <CardSettings
      form={form}
      groups={groups}
      {...(omit ? { omit } : {})}
      {...(collapseLabel ? { collapseLabel } : {})}
    />
  )
}

function Switch({ switchKey }: { switchKey: string }) {
  const form = useSettingsDraft()
  return <ModuleSwitch form={form} switchKey={switchKey} />
}

/** The proxy module on, which is what makes its settings available at all. */
function proxyOn(overrides: Partial<Parameters<typeof makeSettings>[0]> = {}) {
  return settingsRoutes(makeSettings({ 'proxy.enabled': true, ...overrides }))
}

describe('which settings a card puts in the open', () => {
  it('shows the basic ones and keeps the advanced behind a disclosure', async () => {
    const { container, getByLabelText, getByText } = await renderAgent(
      <Card groups={['proxy']} omit={['proxy.enabled']} />,
      proxyOn(),
    )

    // Basic: the one setting worth a glance, directly on the card.
    const basic = container.querySelector('.card-settings > .card-settings-fields')
    expect(within(basic as HTMLElement).getByLabelText('Proxy address')).toBeInTheDocument()

    // Advanced: inside the disclosure and shut. A native <details> keeps its children
    // mounted and lets the browser hide them, so the closed state is the assertion --
    // querying for absence would pass for a disclosure stuck permanently open.
    const details = container.querySelector('details.advanced') as HTMLDetailsElement
    expect(details.open).toBe(false)
    expect(within(details).getByLabelText('Resolve names with')).toBeInTheDocument()

    fireEvent.click(getByText(/Advanced settings/))
    await settle()

    expect(details.open).toBe(true)
    expect(getByLabelText('Resolve names with')).toBeInTheDocument()
  })

  // The switch that governs the module lives in the card's head, so rendering it in the
  // body as well would put two controls for one value on one card.
  it('leaves out the keys the card renders elsewhere', async () => {
    const { queryByLabelText } = await renderAgent(
      <Card groups={['proxy']} omit={['proxy.enabled']} />,
      proxyOn(),
    )

    expect(queryByLabelText('Tailnet proxy')).not.toBeInTheDocument()
  })

  it('renders nothing at all when the module is off and has no available settings', async () => {
    const { container } = await renderAgent(
      <Card groups={['proxy']} omit={['proxy.enabled']} />,
      settingsRoutes(makeSettings()),
    )

    expect(container.querySelector('.card-settings')).toBeNull()
  })
})

// Two kinds of control, two moments to write. A switch has one gesture that means "I have
// decided"; a text box is half-typed for as long as somebody is typing, and writing on
// every keystroke would send the agent a stream of values nobody chose.
describe('when a control applies', () => {
  it('writes a switch as soon as it is used, carrying only that key', async () => {
    const { getByLabelText, agent } = await renderAgent(
      <Card groups={['proxy']} omit={['proxy.enabled']} />,
      {
        ...proxyOn(),
        'PUT /api/settings': makeSettingsResponse({ 'proxy.enabled': true }),
      },
    )

    fireEvent.click(getByLabelText('Require a password'))
    await settle()

    expect(agent.bodyOf<SettingsPatch>('PUT /api/settings')).toEqual({
      'proxy.requireToken': true,
    })
  })

  // A reference to a connection, a device or a resolver profile is a select whose choices
  // the agent fills at run time. It is the same one gesture a switch is, and leaving it
  // behind a Save is what makes choosing a different connection to carry this machine's
  // internet traffic look like a picker that does nothing.
  it('writes a filled reference picker as soon as it is used', async () => {
    const routes = settingsRoutes(
      makeSettings({ 'egress.mode': 'tunnel', 'egress.tunnelId': 'tn_here' }),
    )
    const schema = routes['GET /api/settings/schema'] as ReturnType<typeof makeSettingsSchema>

    const { getByLabelText, agent } = await renderAgent(<Card groups={['egress']} />, {
      ...routes,
      'GET /api/settings/schema': {
        ...schema,
        fields: schema.fields.map((f) =>
          f.key === 'egress.tunnelId'
            ? {
                ...f,
                options: [
                  { value: 'tn_here', label: 'Here' },
                  { value: 'tn_there', label: 'There' },
                ],
              }
            : f,
        ),
      },
      'PUT /api/settings': makeSettingsResponse({
        'egress.mode': 'tunnel',
        'egress.tunnelId': 'tn_there',
      }),
    })

    fireEvent.change(getByLabelText('Connection carrying it'), { target: { value: 'tn_there' } })
    await settle()

    expect(agent.bodyOf<SettingsPatch>('PUT /api/settings')).toEqual({
      'egress.tunnelId': 'tn_there',
    })
  })

  // The same picker with nothing to pick from degrades to a text box, and a text box
  // written on every keystroke sends the agent a stream of half-typed values.
  it('holds an unfilled reference picker until Save', async () => {
    const { getByLabelText, getByText, agent } = await renderAgent(
      <Card groups={['egress']} />,
      settingsRoutes(makeSettings({ 'egress.mode': 'tunnel' })),
    )

    fireEvent.change(getByLabelText('Connection carrying it'), { target: { value: 'tn_typed' } })
    await settle()

    expect(agent.countOf('PUT /api/settings')).toBe(0)
    expect(getByText('Save')).toBeInTheDocument()
  })

  it('holds a typed value until Save', async () => {
    const { getByLabelText, getByText, agent } = await renderAgent(
      <Card groups={['proxy']} omit={['proxy.enabled']} />,
      {
        ...proxyOn(),
        'PUT /api/settings': makeSettingsResponse({ 'proxy.enabled': true }),
      },
    )

    fireEvent.click(getByText(/Advanced settings/))
    fireEvent.change(getByLabelText('Proxy address'), { target: { value: '127.0.0.1:9999' } })
    await settle()

    expect(agent.countOf('PUT /api/settings')).toBe(0)

    fireEvent.click(getByText('Save'))
    await settle()

    expect(agent.bodyOf<SettingsPatch>('PUT /api/settings')).toEqual({
      'proxy.listenAddr': '127.0.0.1:9999',
    })
  })

  // A Save with nothing behind it is a button that looks like it does something.
  it('offers no Save until something is waiting on it', async () => {
    const { getByLabelText, getByText, queryByText } = await renderAgent(
      <Card groups={['proxy']} omit={['proxy.enabled']} />,
      proxyOn(),
    )

    expect(queryByText('Save')).not.toBeInTheDocument()

    fireEvent.click(getByText(/Advanced settings/))
    fireEvent.change(getByLabelText('Proxy address'), { target: { value: '127.0.0.1:9999' } })
    await settle()

    expect(getByText('Save')).toBeInTheDocument()
  })
})

// The single reason a card's Save is scoped rather than the whole draft. Every card
// shares one form, so a Save that sent everything dirty would ship an edit the user made
// on another card and deliberately never submitted.
it('saves only the groups its own card owns', async () => {
  function TwoCards() {
    const form = useSettingsDraft()
    return (
      <>
        <div data-testid="proxy">
          <CardSettings form={form} groups={['proxy']} omit={['proxy.enabled']} />
        </div>
        <div data-testid="identity">
          <CardSettings form={form} groups={['identity']} />
        </div>
      </>
    )
  }

  const { getByLabelText, getAllByText, getByTestId, agent } = await renderAgent(<TwoCards />, {
    ...proxyOn(),
    'PUT /api/settings': makeSettingsResponse({ 'proxy.enabled': true }),
  })

  // An edit on the identity card, left unsaved on purpose.
  fireEvent.change(getByLabelText('Device name'), { target: { value: 'renamed-box' } })
  // And an edit on the proxy card, which is the one being saved.
  fireEvent.click(getAllByText(/Advanced settings/)[0] as HTMLElement)
  fireEvent.change(getByLabelText('Proxy address'), { target: { value: '127.0.0.1:9999' } })
  await settle()

  // Both cards are dirty, so both offer a Save. Pressing the proxy card's is the point.
  fireEvent.click(within(getByTestId('proxy')).getByText('Save'))
  await settle()

  const body = agent.bodyOf<SettingsPatch>('PUT /api/settings')
  expect(body).toEqual({ 'proxy.listenAddr': '127.0.0.1:9999' })
  expect(body).not.toHaveProperty('hostname')
})

describe('the switch in a card head', () => {
  it('reflects what the module is set to', async () => {
    const { getByLabelText } = await renderAgent(
      <Switch switchKey="proxy.enabled" />,
      proxyOn(),
    )

    expect(getByLabelText('Tailnet proxy')).toBeChecked()
  })

  it('writes the module switch on its own', async () => {
    const { getByLabelText, agent } = await renderAgent(<Switch switchKey="proxy.enabled" />, {
      ...settingsRoutes(makeSettings()),
      'PUT /api/settings': makeSettingsResponse({ 'proxy.enabled': true }),
    })

    fireEvent.click(getByLabelText('Tailnet proxy'))
    await settle()

    expect(agent.bodyOf<SettingsPatch>('PUT /api/settings')).toEqual({ 'proxy.enabled': true })
  })
})

// Some cards are read first and configured rarely -- the connection card answers "am I on
// the tailnet", and the name and credentials it enrolled with are set once. Everything
// behind one shut disclosure keeps the answer at the top where it is wanted.
describe('a card that keeps all of its settings folded away', () => {
  it('puts every setting behind one disclosure, shut', async () => {
    const { container } = await renderAgent(
      <Card groups={['proxy']} omit={['proxy.enabled']} collapseLabel="Proxy settings" />,
      proxyOn(),
    )

    const outer = container.querySelector('.card-settings > details.advanced') as HTMLDetailsElement
    expect(outer).toBeInTheDocument()
    expect(outer.open).toBe(false)
    expect(outer.querySelector('summary')).toHaveTextContent('Proxy settings')
  })

  // The count is what says the disclosure is worth opening: a label alone gives no reason
  // to look, and every one of these cards has a different number behind it.
  it('says how many settings are folded away', async () => {
    const { container } = await renderAgent(
      <Card groups={['proxy']} omit={['proxy.enabled']} collapseLabel="Proxy settings" />,
      proxyOn(),
    )

    const count = container.querySelector('.card-settings > details.advanced > summary .count')
    expect(Number(count?.textContent)).toBeGreaterThan(0)
  })

  // Cards whose every setting is advanced -- the system resolver is one -- would otherwise
  // put a disclosure inside a disclosure, so the setting takes two clicks and the inner
  // label says less than the outer one already did.
  it('does not fold an advanced-only card away twice', async () => {
    const { container, getByText } = await renderAgent(
      <Card groups={['systemdns']} omit={['systemDns.enabled', 'systemDns.profile']} collapseLabel="System resolver settings" />,
      settingsRoutes(makeSettings({ 'systemDns.enabled': true })),
    )

    fireEvent.click(getByText(/System resolver settings/))

    const outer = container.querySelector('.card-settings > details.advanced') as HTMLDetailsElement
    expect(outer.querySelector('details.advanced')).toBeNull()
    expect(outer.querySelector('.card-settings-fields')).toBeInTheDocument()
  })

  it('leaves the basic settings in the open when no label is given', async () => {
    const { container } = await renderAgent(
      <Card groups={['proxy']} omit={['proxy.enabled']} />,
      proxyOn(),
    )

    expect(container.querySelector('.card-settings > .card-settings-fields')).toBeInTheDocument()
  })
})
