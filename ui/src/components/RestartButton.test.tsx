// SPDX-License-Identifier: MIT

import { fireEvent } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'

import { failWith, renderAgent, settle } from '../test/agent'
import { RestartButton } from './RestartButton'

describe('restarting app-tail', () => {
  // Restarting drops every forward and every proxy connection, and the page asking for
  // it goes away too. That is not something a stray click should be able to do.
  it('asks before it restarts anything', async () => {
    const { getByRole, agent } = await renderAgent(<RestartButton />)

    fireEvent.click(getByRole('button', { name: 'Restart app-tail' }))
    await settle()

    expect(getByRole('dialog')).toHaveAccessibleName('Restart app-tail?')
    expect(agent.countOf('POST /api/restart-app')).toBe(0)
  })

  it('says what is interrupted before asking to confirm', async () => {
    const { getByRole, getByText } = await renderAgent(<RestartButton />)

    fireEvent.click(getByRole('button', { name: 'Restart app-tail' }))
    await settle()

    expect(getByText(/Every forward and every proxy connection is closed/)).toBeInTheDocument()
  })

  it('restarts once confirmed', async () => {
    const { getByRole, agent } = await renderAgent(<RestartButton />, {
      'POST /api/restart-app': { restarting: true },
    })

    fireEvent.click(getByRole('button', { name: 'Restart app-tail' }))
    await settle()
    fireEvent.click(getByRole('button', { name: 'Restart' }))
    await settle()

    expect(agent.countOf('POST /api/restart-app')).toBe(1)
  })

  // The agent stops answering the moment it takes the request, so there is no second
  // response to wait for. Leaving the button live would invite a click that reaches a
  // process which is already gone.
  it('holds a waiting state rather than reporting a result it cannot see', async () => {
    const { getByRole, queryByRole } = await renderAgent(<RestartButton />, {
      'POST /api/restart-app': { restarting: true },
    })

    fireEvent.click(getByRole('button', { name: 'Restart app-tail' }))
    await settle()
    fireEvent.click(getByRole('button', { name: 'Restart' }))
    await settle()

    expect(queryByRole('dialog')).not.toBeInTheDocument()
    expect(getByRole('button', { name: 'Restarting…' })).toBeDisabled()
  })

  // A refusal means the process is still up and still serving this page, so it is the
  // one outcome worth reporting -- and the dialog has to stay to report it.
  it('keeps the dialog open and states the reason when the agent refuses', async () => {
    const { getByRole, getByText } = await renderAgent(<RestartButton />, {
      'POST /api/restart-app': failWith(503, 'agent is already shutting down'),
    })

    fireEvent.click(getByRole('button', { name: 'Restart app-tail' }))
    await settle()
    fireEvent.click(getByRole('button', { name: 'Restart' }))
    await settle()

    expect(getByRole('dialog')).toBeInTheDocument()
    expect(getByText(/already shutting down/)).toBeInTheDocument()
    expect(getByRole('button', { name: 'Restart app-tail' })).toBeEnabled()
  })

  // The page and the binary go away together, so a page that merely resumed polling
  // could be a build that no longer matches what is serving it.
  it('reloads once the agent answers again', async () => {
    vi.useFakeTimers()
    const reload = vi.fn()
    Object.defineProperty(window, 'location', {
      configurable: true,
      value: { ...window.location, reload },
    })
    try {
      const { getByRole } = await renderAgent(<RestartButton />, {
        'POST /api/restart-app': { restarting: true },
        // 503 is what a healthy agent with no tailnet answers, and it still means the
        // process is back. Reading it as "not yet" would leave the page waiting forever.
        'GET /healthz': failWith(503, 'tailnet node is not running'),
      })

      fireEvent.click(getByRole('button', { name: 'Restart app-tail' }))
      await settle()
      fireEvent.click(getByRole('button', { name: 'Restart' }))
      await settle()

      await vi.advanceTimersByTimeAsync(1000)
      await settle()

      expect(reload).toHaveBeenCalled()
    } finally {
      vi.useRealTimers()
    }
  })
})
