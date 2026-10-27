// SPDX-License-Identifier: MIT

import { act, fireEvent } from '@testing-library/react'
import { describe, expect, it, onTestFinished, vi } from 'vitest'

import {
  deferred,
  failWith,
  makeSettings,
  renderAgent,
  settle,
  stubClipboard,
} from '../test/agent'
import type { AgentView, Routes } from '../test/agent'
import { TagSetupDialog } from './TagSetupDialog'
import type { PolicyBootstrapRequest, PolicyPlanView } from '../api'

async function open(routes: Routes = {}): Promise<AgentView> {
  return renderAgent(<TagSetupDialog onClose={() => {}} />, routes)
}

/** credentials fills the OAuth client the one-click apply needs. */
function credentials(view: AgentView, id = 'tskey-client-id', secret = 'tskey-client-secret'): void {
  fireEvent.change(view.getByLabelText('OAuth client id'), { target: { value: id } })
  fireEvent.change(view.getByLabelText('OAuth client secret'), { target: { value: secret } })
}

function press(view: AgentView, name: string): void {
  fireEvent.click(view.getByRole('button', { name }))
}

const wouldChange: PolicyPlanView = {
  summary: 'add tag:app-tail to tagOwners and grant it access',
  addTagOwner: true,
  addGrant: true,
  changed: true,
}

// The dialog's whole job is telling the user which tags their tailnet has to define.
// Naming the wrong ones sends them to the admin console to create a tag their nodes
// will never advertise, and the sign-in keeps failing with no clue why.
describe('the tags the dialog tells you to create', () => {
  it('names the tags this node is actually configured with', async () => {
    const { getByRole } = await open({
      'GET /api/settings': makeSettings({ tags: ['tag:prod', 'tag:edge'] }),
    })

    const dialog = getByRole('dialog')
    expect(dialog).toHaveTextContent('tag:prod')
    expect(dialog).toHaveTextContent('tag:edge')
    // Plural, because "share the tag tag:prod, tag:edge" reads as one malformed tag.
    expect(dialog).toHaveTextContent('app-tail devices share the tags')
  })

  it.each([
    ['none are configured', makeSettings({ tags: [] })],
    ['settings cannot be read', failWith(500, 'the config is unreadable')],
  ])('falls back to the built-in tag when %s', async (_case, route) => {
    const { getByRole } = await open({ 'GET /api/settings': route })

    const dialog = getByRole('dialog')
    expect(dialog).toHaveTextContent('tag:app-tail')
    expect(dialog).toHaveTextContent('app-tail devices share the tag ')
  })

  // The admin console's Create tag field takes the bare name and renders the prefix
  // itself; typing "tag:app-tail" there produces a tag called tag:tag:app-tail.
  it('strips the prefix in the step that says what to type into the console', async () => {
    const { container } = await open({ 'GET /api/settings': makeSettings({ tags: ['tag:prod'] }) })

    const steps = container.querySelector('.howto')
    expect(steps).toHaveTextContent('Set the tag name to prod')
    expect(steps).not.toHaveTextContent('Set the tag name to tag:prod')
  })

  it('writes a policy snippet that owns every configured tag', async () => {
    const { container } = await open({
      'GET /api/settings': makeSettings({ tags: ['tag:prod', 'tag:edge'] }),
    })

    const snippet = container.querySelector('.snippet pre')?.textContent ?? ''
    expect(snippet).toContain('"tag:prod": ["autogroup:admin"]')
    expect(snippet).toContain('"tag:edge": ["autogroup:admin"]')
    // The grant is what lets the tagged devices reach one another; a tagOwners entry
    // on its own leaves a fleet that can sign in but not connect.
    expect(snippet).toContain('"src": ["tag:prod", "tag:edge"]')
  })

  // The flag is single-valued, so a two-tag fleet needs two invocations. One command
  // naming both tags is a command that silently sets up only one of them.
  it('writes one CLI invocation per tag, with the secret passed by file', async () => {
    const { container } = await open({
      'GET /api/settings': makeSettings({ tags: ['tag:prod', 'tag:edge'] }),
    })

    const cli = container.querySelectorAll('.snippet pre')[1]?.textContent ?? ''
    expect(cli).toContain('--tag tag:prod')
    expect(cli).toContain('--tag tag:edge')
    expect(cli).toContain('--client-secret-file')
    expect(cli).not.toContain('--client-secret ')
  })
})

describe('the one-click apply', () => {
  it('refuses to call the agent without both halves of the credential', async () => {
    const view = await open()

    press(view, 'Preview')
    await settle()
    expect(view.getByText('Enter both the OAuth client id and secret.')).toBeInTheDocument()
    expect(view.agent.countOf('POST /api/policy/preview')).toBe(0)

    fireEvent.change(view.getByLabelText('OAuth client id'), { target: { value: 'only-the-id' } })
    press(view, 'Preview')
    await settle()

    expect(view.agent.countOf('POST /api/policy/preview')).toBe(0)
  })

  // A preview is a dry run. Sending the tags the dialog is showing -- rather than
  // letting the agent guess -- is what makes the preview describe the same write
  // the Apply button will perform.
  it('previews against the tags on screen without writing anything', async () => {
    const view = await open({
      'GET /api/settings': makeSettings({ tags: ['tag:prod'] }),
      'POST /api/policy/preview': wouldChange,
    })

    credentials(view)
    press(view, 'Preview')
    await settle()

    expect(view.agent.bodyOf<PolicyBootstrapRequest>('POST /api/policy/preview')).toEqual({
      clientId: 'tskey-client-id',
      clientSecret: 'tskey-client-secret',
      tags: ['tag:prod'],
    })
    expect(view.agent.countOf('POST /api/policy/apply')).toBe(0)
    expect(view.getByText(/Will add tag:app-tail to tagOwners/)).toBeInTheDocument()
  })

  it('applies what the preview described and says it is done', async () => {
    const view = await open({
      'POST /api/policy/preview': wouldChange,
      'POST /api/policy/apply': { ...wouldChange },
    })

    credentials(view)
    press(view, 'Preview')
    await settle()
    press(view, 'Apply')
    await settle()

    expect(view.agent.countOf('POST /api/policy/apply')).toBe(1)
    expect(view.getByText(/Applied: add tag:app-tail to tagOwners/)).toBeInTheDocument()
  })

  it('distinguishes a policy that already allowed the fleet from one it changed', async () => {
    const view = await open({
      'POST /api/policy/preview': { ...wouldChange, changed: false },
    })

    credentials(view)
    press(view, 'Preview')
    await settle()

    expect(view.getByText('The policy already allows this fleet; nothing to do.')).toBeInTheDocument()
  })

  it('shows the notes the agent attached to its plan', async () => {
    const view = await open({
      'POST /api/policy/preview': {
        ...wouldChange,
        notes: ['the grant dst is illustrative; scope it in the admin console'],
      },
    })

    credentials(view)
    press(view, 'Preview')
    await settle()

    expect(
      view.getByText('the grant dst is illustrative; scope it in the admin console'),
    ).toBeInTheDocument()
  })
})

// Apply writes to the tailnet's live ACL policy. Every one of these four conditions
// is a case where pressing it would write something other than what the user was
// shown, so each has to hold the button shut on its own.
describe('when Apply is allowed to be pressed', () => {
  it('stays shut until a preview has been seen', async () => {
    const view = await open()

    credentials(view)

    expect(view.getByRole('button', { name: 'Apply' })).toBeDisabled()
  })

  it('stays shut when the preview found nothing to change', async () => {
    const view = await open({ 'POST /api/policy/preview': { ...wouldChange, changed: false } })

    credentials(view)
    press(view, 'Preview')
    await settle()

    expect(view.getByRole('button', { name: 'Apply' })).toBeDisabled()
  })

  it('shuts again once the policy has been applied', async () => {
    const view = await open({
      'POST /api/policy/preview': wouldChange,
      'POST /api/policy/apply': { ...wouldChange },
    })

    credentials(view)
    press(view, 'Preview')
    await settle()
    expect(view.getByRole('button', { name: 'Apply' })).toBeEnabled()

    press(view, 'Apply')
    await settle()

    expect(view.getByRole('button', { name: 'Apply' })).toBeDisabled()
  })

  it('shuts while a request is in flight', async () => {
    const pending = deferred<PolicyPlanView>()
    const view = await open({ 'POST /api/policy/preview': () => pending.promise })

    credentials(view)
    press(view, 'Preview')
    await settle(1)

    expect(view.getByRole('button', { name: 'Checking…' })).toBeDisabled()
    expect(view.getByRole('button', { name: 'Applying…' })).toBeDisabled()

    pending.resolve(wouldChange)
    await settle()

    expect(view.getByRole('button', { name: 'Preview' })).toBeEnabled()
  })

  // A rejected apply leaves the policy exactly as it was, so the plan the user was
  // shown may no longer be the plan a retry would run. Keeping it on screen invites
  // a second press against a summary that was never re-checked.
  it('retracts the plan when an apply is rejected', async () => {
    const view = await open({
      'POST /api/policy/preview': wouldChange,
      'POST /api/policy/apply': failWith(400, 'the OAuth client lacks the policy_file scope'),
    })

    credentials(view)
    press(view, 'Preview')
    await settle()
    press(view, 'Apply')
    await settle()

    expect(view.getByText('the OAuth client lacks the policy_file scope')).toBeInTheDocument()
    expect(view.queryByText(/Will add/)).not.toBeInTheDocument()
    expect(view.getByRole('button', { name: 'Apply' })).toBeDisabled()
  })

  // The plan was computed for one credential. Editing either half makes it a plan
  // for a request that will never be sent.
  it.each([
    ['the client id', 'OAuth client id'],
    ['the client secret', 'OAuth client secret'],
  ])('retracts the plan when %s is edited', async (_case, label) => {
    const view = await open({ 'POST /api/policy/preview': wouldChange })

    credentials(view)
    press(view, 'Preview')
    await settle()
    expect(view.getByText(/Will add/)).toBeInTheDocument()

    fireEvent.change(view.getByLabelText(label), { target: { value: 'something-else' } })

    expect(view.queryByText(/Will add/)).not.toBeInTheDocument()
    expect(view.getByRole('button', { name: 'Apply' })).toBeDisabled()
  })

  // A preview that fails to reach the agent must not leave a stale plan enabled
  // either.
  it('reports a preview the agent refused', async () => {
    const view = await open({
      'POST /api/policy/preview': failWith(400, 'the tailnet name could not be resolved'),
    })

    credentials(view)
    press(view, 'Preview')
    await settle()

    expect(view.getByText('the tailnet name could not be resolved')).toBeInTheDocument()
    expect(view.getByRole('button', { name: 'Apply' })).toBeDisabled()
  })
})

// A self-hosted control server manages its own ACLs. Offering the admin-console
// walkthrough or the one-click apply there sends the user to a console that has
// nothing to do with their tailnet, and the apply would fail against an API that
// isn't listening.
describe('against a self-hosted control server', () => {
  const headscale = {
    'GET /api/settings': makeSettings({ controlURL: 'https://headscale.example.com' }),
  }

  it('says the console steps do not apply and hides them', async () => {
    const view = await open(headscale)

    expect(view.getByText(/A custom control server is configured/)).toBeInTheDocument()
    expect(view.container.querySelector('.howto')).not.toBeInTheDocument()
  })

  it('withdraws the one-click apply entirely', async () => {
    const view = await open(headscale)

    expect(view.queryByLabelText('OAuth client id')).not.toBeInTheDocument()
    expect(view.queryByRole('button', { name: 'Apply' })).not.toBeInTheDocument()
  })

  // The snippet is the one path that still works, so it must survive.
  it('still offers the policy snippet to paste', async () => {
    const view = await open(headscale)

    expect(view.container.querySelector('.snippet pre')).toHaveTextContent('tagOwners')
  })

  // Tailscale's own control plane spelled out explicitly is not a custom server;
  // treating it as one would withdraw the apply from an ordinary tailnet.
  it('treats the explicit Tailscale URL as the hosted control plane', async () => {
    const view = await open({
      'GET /api/settings': makeSettings({ controlURL: 'https://controlplane.tailscale.com' }),
    })

    expect(view.getByLabelText('OAuth client id')).toBeInTheDocument()
  })
})

describe('copying a snippet', () => {
  // The snippet is long, multi-line HuJSON. Copying it by hand out of a <pre> is
  // where a truncated policy comes from.
  it('puts the policy snippet on the clipboard and confirms it', async () => {
    const clipboard = stubClipboard()
    vi.useFakeTimers()
    onTestFinished(() => {
      vi.useRealTimers()
    })

    const view = await open({ 'GET /api/settings': makeSettings({ tags: ['tag:prod'] }) })
    const copy = view.getAllByRole('button', { name: 'Copy' })[0]!

    fireEvent.click(copy)
    await settle()

    expect(clipboard.writeText).toHaveBeenCalledWith(
      expect.stringContaining('"tag:prod": ["autogroup:admin"]'),
    )
    expect(view.getAllByRole('button', { name: 'Copied' })[0]).toBeInTheDocument()
  })

  // The confirmation has to time out, or the button says "Copied" forever and the
  // user cannot tell whether a second copy registered.
  it('goes back to offering a copy after a moment', async () => {
    stubClipboard()
    vi.useFakeTimers()
    onTestFinished(() => {
      vi.useRealTimers()
    })

    const view = await open()
    fireEvent.click(view.getAllByRole('button', { name: 'Copy' })[0]!)
    await settle()
    expect(view.getAllByRole('button', { name: 'Copied' })[0]).toBeInTheDocument()

    await act(async () => {
      await vi.advanceTimersByTimeAsync(1500)
    })

    expect(view.getAllByRole('button', { name: 'Copy' })[0]).toBeInTheDocument()
  })

  // Clipboard access is denied in plenty of contexts. The text stays selectable, so
  // a rejection is not worth an error -- but it must not claim the copy succeeded.
  it('does not claim success when the clipboard refuses', async () => {
    const clipboard = stubClipboard()
    clipboard.writeText.mockRejectedValue(new Error('clipboard access denied'))

    const view = await open()
    fireEvent.click(view.getAllByRole('button', { name: 'Copy' })[0]!)
    await settle()

    expect(view.queryByRole('button', { name: 'Copied' })).not.toBeInTheDocument()
  })
})
