// SPDX-License-Identifier: MIT

// The settings form's login item, which is the one control that does not go through the
// settings document: it is read and written through its own endpoint, and what the agent
// says about it has to reach the switch.

import { act } from '@testing-library/react'
import { describe, expect, it } from 'vitest'

import {
  deferred,
  failWith,
  makeSettingsResponse,
  renderAgent,
  settle,
  type AgentCall,
  type AgentStub,
} from '../../test/agent'
import type { SettingFieldSchema } from '../../api'
import { useSettingsDraft, type SettingsForm } from './useSettingsDraft'

const LOGIN_ITEM: SettingFieldSchema = {
  key: 'startAtLogin',
  viewKey: 'startAtLogin',
  kind: 'bool',
  secret: false,
  readOnly: false,
  derived: false,
  restart: 'none',
  write: 'autostart',
  label: 'Start at login',
  group: 'application',
  tier: 'basic',
  module: 'core',
  help: '',
  available: true,
  availableReason: '',
}

/** Renders a probe that hands the live form back, so a test can read the switch. */
async function drive(
  routes: Record<string, unknown>,
): Promise<{ form: () => SettingsForm; agent: AgentStub }> {
  let latest: SettingsForm | undefined
  function Probe() {
    latest = useSettingsDraft()
    return null
  }
  const { agent } = await renderAgent(<Probe />, routes)
  const form = () => {
    if (latest === undefined) throw new Error('the form never rendered')
    return latest
  }
  return { form, agent }
}

describe('the login item on the settings form', () => {
  it('shows the switch as the agent reports it', async () => {
    const { form } = await drive({ 'GET /api/autostart': { enabled: true } })

    expect(form().bind(LOGIN_ITEM).value).toBe(true)
    expect(form().bind(LOGIN_ITEM).error).toBeUndefined()
  })

  // An installed login item can still be one that will not start app-tail: wrong rights
  // for the network mode, or a binary that has moved. Nothing on the machine says so until
  // the next login, so a switch reading "on" with nothing beside it is the whole bug.
  it('reports a login item that is installed and broken', async () => {
    const { form } = await drive({
      'GET /api/autostart': {
        enabled: true,
        problem: 'It was installed for the other network mode.',
      },
    })

    expect(form().bind(LOGIN_ITEM).value).toBe(true)
    expect(form().bind(LOGIN_ITEM).error).toBe('It was installed for the other network mode.')
  })

  // The fault is recomputed from the machine on every answer, so one that has been
  // corrected has to stop being shown rather than stay on screen until a reload.
  it('clears the fault once the agent stops reporting one', async () => {
    const { form } = await drive({
      'GET /api/autostart': {
        enabled: true,
        problem: 'It names a program that is no longer there.',
      },
      'POST /api/autostart': { enabled: true },
    })
    expect(form().bind(LOGIN_ITEM).error).toBe('It names a program that is no longer there.')

    act(() => form().bind(LOGIN_ITEM).onChange(true))
    await settle()

    expect(form().bind(LOGIN_ITEM).error).toBeUndefined()
  })

  // A platform with no login items answers the read with a refusal. That is a fact about
  // this machine, so it lands on the switch alone: the rest of the form still loads, and
  // the switch stays held rather than offering a guess someone could click.
  it('keeps the rest of the form when the login item cannot be read', async () => {
    const { form } = await drive({
      'GET /api/autostart': failWith(501, 'login items are not supported on this platform'),
    })

    expect(form().loaded).toBe(true)
    expect(form().error).toBeUndefined()
    expect(form().bind(LOGIN_ITEM).error).toBe('login items are not supported on this platform')
    expect(form().bind(LOGIN_ITEM).disabled).toBe(true)
    expect(form().bind(LOGIN_ITEM).value).toBe(false)
  })

  it('puts a refused write on the switch and leaves it where it was', async () => {
    const { form } = await drive({
      'GET /api/autostart': { enabled: false },
      'POST /api/autostart': failWith(500, 'the login item could not be written'),
    })

    act(() => form().bind(LOGIN_ITEM).onChange(true))
    await settle()

    expect(form().bind(LOGIN_ITEM).value).toBe(false)
    expect(form().bind(LOGIN_ITEM).error).toBe('the login item could not be written')
    expect(form().error).toBeUndefined()
  })

  it('sends the switch position it was given, not the one it had', async () => {
    const { form, agent } = await drive({
      'GET /api/autostart': { enabled: true },
      'POST /api/autostart': (call: AgentCall) => JSON.parse(call.body ?? '{}') as unknown,
    })

    act(() => form().bind(LOGIN_ITEM).onChange(false))
    await settle()

    expect(agent.bodyOf('POST /api/autostart')).toEqual({ enabled: false })
    expect(form().bind(LOGIN_ITEM).value).toBe(false)
  })
})

// A saved identity change is stored and not yet in force until the node is rebuilt. The
// form is what runs that rebuild, so it has to say when it is running, retire the notice
// only when the agent confirms, and say why when it does not.
describe('reconnecting the node from the settings form', () => {
  it('reports the run, then retires the pending notice on success', async () => {
    const restart = deferred<{ backendState: string }>()
    const { form } = await drive({
      'PUT /api/settings': makeSettingsResponse({ nodeRestart: true }),
      'POST /api/restart': () => restart.promise,
    })
    await act(async () => form().applyPatch({ hostname: 'other' }))
    expect(form().nodeRestartPending).toBe(true)

    let done: Promise<void> | undefined
    act(() => {
      done = form().restartNode()
    })
    expect(form().restarting).toBe(true)

    restart.resolve({ backendState: 'Running' })
    await settle()
    await done

    expect(form().restarting).toBe(false)
    expect(form().nodeRestartPending).toBe(false)
    expect(form().error).toBeUndefined()
  })

  it('keeps the notice and names the refusal when the node will not restart', async () => {
    const { form } = await drive({
      'PUT /api/settings': makeSettingsResponse({ nodeRestart: true }),
      'POST /api/restart': failWith(503, 'the tailnet node is not running'),
    })
    await act(async () => form().applyPatch({ hostname: 'other' }))

    await act(async () => form().restartNode())

    expect(form().restarting).toBe(false)
    expect(form().nodeRestartPending).toBe(true)
    expect(form().error).toBe('the tailnet node is not running')
  })
})
