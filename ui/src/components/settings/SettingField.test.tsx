// SPDX-License-Identifier: MIT

import { fireEvent } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'

import { renderScoped } from '../../test/agent'
import type { SettingFieldSchema } from '../../api'
import { SettingField } from './SettingField'
import type { FieldBinding } from './useSettingsDraft'

function field(overrides: Partial<SettingFieldSchema> & { key: string }): SettingFieldSchema {
  return {
    viewKey: overrides.key,
    kind: 'string',
    secret: false,
    readOnly: false,
    derived: false,
    restart: 'none',
    write: 'patch',
    label: overrides.key,
    group: 'identity',
    tier: 'basic',
    module: 'core',
    help: '',
    ...overrides,
  }
}

function binding(overrides: Partial<FieldBinding> = {}): FieldBinding {
  return {
    value: '',
    example: '',
    onChange: () => {},
    stored: false,
    error: undefined,
    disabled: false,
    ...overrides,
  }
}

describe('a setting whose type this build has never heard of', () => {
  // A dashboard older than the agent it is talking to still has to let the user reach
  // the setting. Rendering nothing would make the setting unreachable from the only
  // surface most users have, with no clue that anything is missing.
  const unknown = field({
    key: 'rotateInterval',
    kind: 'duration' as SettingFieldSchema['kind'],
    label: 'Rotation interval',
    help: 'How often the exit node changes.',
  })

  it('is still editable, through a plain text box', () => {
    const onChange = vi.fn()
    const view = renderScoped(
      <SettingField field={unknown} {...binding({ value: '15m', onChange })} />,
    )

    const box = view.getByLabelText('Rotation interval')
    expect(box).toHaveValue('15m')

    fireEvent.change(box, { target: { value: '30m' } })
    expect(onChange).toHaveBeenCalledWith('30m')
  })

  it('says the dashboard is the one that is out of date', () => {
    const view = renderScoped(<SettingField field={unknown} {...binding()} />)

    expect(view.getByText(/does not know the "duration" setting type/)).toBeInTheDocument()
    expect(view.getByText(/Update the app/)).toBeInTheDocument()
  })

  it('does not say that about a type it does know', () => {
    const view = renderScoped(<SettingField field={field({ key: 'hostname' })} {...binding()} />)

    expect(view.queryByText(/does not know/)).not.toBeInTheDocument()
  })
})

describe('a read-only fact', () => {
  const fact = field({
    key: 'effectiveHostname',
    label: 'Effective device name',
    write: 'none',
    readOnly: true,
  })

  // Rendering a fact in a disabled input invites the user to try to edit something the
  // agent will never accept, and then to wonder why the box is dead.
  it('is not an input at all', () => {
    const view = renderScoped(<SettingField field={fact} {...binding({ value: 'app-tail-box' })} />)

    expect(view.queryByLabelText('Effective device name')).not.toBeInTheDocument()
    expect(view.container).toHaveTextContent('app-tail-box')
  })

  // A fact with no value yet -- a node that has not named itself -- must read as
  // absent rather than as a blank line the user cannot tell apart from a layout bug.
  it('reads as absent rather than blank when there is nothing to report', () => {
    const view = renderScoped(<SettingField field={fact} {...binding({ value: '' })} />)

    expect(view.container).toHaveTextContent('—')
  })
})

describe('the bounds a number control offers', () => {
  // The agent enforces the same limits. Offering them in the control is what stops the
  // user discovering them from a rejected save of a whole form.
  it('come from the field’s declared constraint', () => {
    const f = field({
      key: 'udpBufferBytes',
      kind: 'int',
      label: 'UDP buffer (bytes)',
      constraint: { min: 1, max: 65535 },
    })
    const view = renderScoped(<SettingField field={f} {...binding({ value: '65535' })} />)

    const box = view.getByLabelText('UDP buffer (bytes)')
    expect(box).toHaveAttribute('min', '1')
    expect(box).toHaveAttribute('max', '65535')
  })

  it('are simply absent when the field declares none', () => {
    const f = field({ key: 'udpBufferBytes', kind: 'int', label: 'UDP buffer (bytes)' })
    const view = renderScoped(<SettingField field={f} {...binding({ value: '1' })} />)

    expect(view.getByLabelText('UDP buffer (bytes)')).not.toHaveAttribute('min')
  })
})

describe('a setting that picks from a fixed set', () => {
  const scope = field({
    key: 'proxy.scope',
    kind: 'enum',
    label: 'Proxy scope',
    options: [
      { value: 'tailnet', label: 'Tailnet only', help: 'Refuses anything the tailnet does not route.' },
      { value: 'all', label: 'Everything', help: 'Also carries public traffic.' },
    ],
  })

  // The whole point of declaring options in the registry is that the picker cannot
  // offer a value the agent would refuse. A free-text box for a fixed set is how a
  // typo becomes a rejected save.
  it('offers exactly the choices the schema declares', () => {
    const view = renderScoped(<SettingField field={scope} {...binding({ value: 'tailnet' })} />)

    const picker = view.getByLabelText('Proxy scope')
    expect(picker).toHaveValue('tailnet')
    expect(
      Array.from(picker.querySelectorAll('option')).map((o) => [o.value, o.textContent]),
    ).toEqual([
      ['tailnet', 'Tailnet only'],
      ['all', 'Everything'],
    ])
  })

  it('reports the chosen value, not its label', () => {
    const onChange = vi.fn()
    const view = renderScoped(
      <SettingField field={scope} {...binding({ value: 'tailnet', onChange })} />,
    )

    fireEvent.change(view.getByLabelText('Proxy scope'), { target: { value: 'all' } })
    expect(onChange).toHaveBeenCalledWith('all')
  })

  // Two options whose labels are both plausible are indistinguishable without this;
  // choosing between them is exactly where a security-relevant setting goes wrong.
  it('explains what the selected choice does', () => {
    const view = renderScoped(<SettingField field={scope} {...binding({ value: 'all' })} />)

    expect(view.container).toHaveTextContent('Also carries public traffic.')
    expect(view.container).not.toHaveTextContent('Refuses anything the tailnet does not route.')
  })

  // A newer agent may store a choice this build has no option for. Dropping it would
  // make the picker report a setting other than the one in force -- and then write the
  // substitute on the next save.
  it('keeps showing a stored value it has no option for', () => {
    const view = renderScoped(<SettingField field={scope} {...binding({ value: 'exitNode' })} />)

    expect(view.getByLabelText('Proxy scope')).toHaveValue('exitNode')
  })

  // An enum whose options a build predates would otherwise render an empty picker: a
  // control that shows nothing and can select nothing.
  it('degrades to a text box when the schema carries no choices', () => {
    const onChange = vi.fn()
    const bare = field({ key: 'proxy.scope', kind: 'enum', label: 'Proxy scope' })
    const view = renderScoped(<SettingField field={bare} {...binding({ value: 'all', onChange })} />)

    const box = view.getByLabelText('Proxy scope')
    expect(box.tagName).toBe('INPUT')

    fireEvent.change(box, { target: { value: 'tailnet' } })
    expect(onChange).toHaveBeenCalledWith('tailnet')
  })
})

describe('a secret control', () => {
  const secret = field({
    key: 'authKey',
    kind: 'secret',
    secret: true,
    viewKey: 'hasAuthKey',
    label: 'Auth key',
  })

  // The agent never sends a stored secret, so the box can only report whether one
  // exists. Saying nothing would leave the user unable to tell a configured install
  // from an unconfigured one.
  it.each([
    [true, 'stored — type to replace'],
    [false, 'not set'],
  ])('reports stored=%s without ever showing the value', (stored, expected) => {
    const view = renderScoped(<SettingField field={secret} {...binding({ stored })} />)

    const box = view.getByLabelText('Auth key')
    expect(box).toHaveAttribute('placeholder', expected)
    expect(box).toHaveValue('')
  })
})

describe('a boolean setting', () => {
  const flag = field({ key: 'ephemeral', kind: 'bool', label: 'Ephemeral node', help: 'why' })

  it('reads as one statement rather than a checkbox with a caption', () => {
    const view = renderScoped(<SettingField field={flag} {...binding({ value: true })} />)

    expect(view.getByLabelText('Ephemeral node')).toBeChecked()
    expect(view.container).toHaveTextContent('why')
  })

  // A switch whose real state has not arrived yet must not be clickable: a guess the
  // user can act on is worse than one they cannot.
  it('cannot be moved while its state is still unknown', () => {
    const view = renderScoped(<SettingField field={flag} {...binding({ disabled: true })} />)

    expect(view.getByLabelText('Ephemeral node')).toBeDisabled()
  })

  it('shows a rejection of its own', () => {
    const view = renderScoped(
      <SettingField field={flag} {...binding({ error: 'not supported here' })} />,
    )

    expect(view.getByText('not supported here')).toBeInTheDocument()
  })
})

describe('a set of connections', () => {
  const members = field({
    key: 'egress.multi.tunnelIds',
    kind: 'tunnelRefList',
    label: 'Connections sharing it',
    options: [
      { value: 'tn_office', label: 'Office' },
      { value: 'tn_lab', label: 'Lab', help: 'A WireGuard connection.' },
      { value: 'tn_home', label: 'Home' },
    ],
  })

  it('offers every connection at once rather than a box to type ids into', () => {
    const view = renderScoped(
      <SettingField field={members} {...binding({ value: 'tn_lab' })} />,
    )

    expect(view.getByLabelText('Lab')).toBeChecked()
    expect(view.getByLabelText('Office')).not.toBeChecked()
    expect(view.getByText('A WireGuard connection.')).toBeInTheDocument()
  })

  it('adds a connection at the end, keeping the order already chosen', () => {
    const onChange = vi.fn()
    const view = renderScoped(
      <SettingField field={members} {...binding({ value: 'tn_home, tn_lab', onChange })} />,
    )

    fireEvent.click(view.getByLabelText('Office'))
    expect(onChange).toHaveBeenCalledWith('tn_home, tn_lab, tn_office')
  })

  it('takes a connection out without disturbing the rest', () => {
    const onChange = vi.fn()
    const view = renderScoped(
      <SettingField
        field={members}
        {...binding({ value: 'tn_home, tn_lab, tn_office', onChange })}
      />,
    )

    fireEvent.click(view.getByLabelText('Lab'))
    expect(onChange).toHaveBeenCalledWith('tn_home, tn_office')
  })

  // The empty set is a value with a meaning of its own, and a blank row of unticked boxes
  // reads equally well as "none of them" -- which is the opposite.
  it('says what choosing nothing means', () => {
    const view = renderScoped(<SettingField field={members} {...binding({ value: '' })} />)

    expect(view.getByText(/every connection that is running takes a share/)).toBeInTheDocument()
  })

  // A stored id this build has no option for is still part of the set. Dropping it from the
  // display would have the next save write it away without anybody asking.
  it('keeps a connection it has no option for, and says so', () => {
    const onChange = vi.fn()
    const view = renderScoped(
      <SettingField field={members} {...binding({ value: 'tn_lab, tn_gone', onChange })} />,
    )

    const orphan = view.getByLabelText('tn_gone')
    expect(orphan).toBeChecked()
    expect(view.getByText(/no longer on offer/)).toBeInTheDocument()

    fireEvent.click(orphan)
    expect(onChange).toHaveBeenCalledWith('tn_lab')
  })

  // A dashboard older than the agent, or an agent with no connections yet: an empty picker
  // would leave the setting unreachable from the only surface most users have.
  it('degrades to a text box when the agent offered no connections', () => {
    const onChange = vi.fn()
    const view = renderScoped(
      <SettingField
        field={field({ ...members, options: [] })}
        {...binding({ value: 'tn_lab', onChange })}
      />,
    )

    const box = view.getByLabelText('Connections sharing it')
    expect(box).toHaveValue('tn_lab')
    fireEvent.change(box, { target: { value: 'tn_lab, tn_home' } })
    expect(onChange).toHaveBeenCalledWith('tn_lab, tn_home')
  })
})

describe('a setting whose value runs to several lines', () => {
  const pem = field({ key: 'tls.certificate', kind: 'text', label: 'Certificate', example: '-----BEGIN CERTIFICATE-----' })

  // A certificate or a key pasted into a single-line box is the half-pasted PEM nobody
  // can spot before saving, and the shape of the box is the only warning there is.
  it('is a multi-line box that keeps the newlines it is given', () => {
    const onChange = vi.fn()
    const view = renderScoped(
      <SettingField field={pem} {...binding({ value: 'line one\nline two', onChange, example: '-----BEGIN' })} />,
    )

    const box = view.getByLabelText('Certificate')
    expect(box.tagName).toBe('TEXTAREA')
    expect(box).toHaveValue('line one\nline two')
    expect(box).toHaveAttribute('placeholder', '-----BEGIN')
    expect(box).toHaveAttribute('spellcheck', 'false')

    fireEvent.change(box, { target: { value: 'a\nb\nc' } })
    expect(onChange).toHaveBeenCalledWith('a\nb\nc')
  })

  it('carries a rejection on the box itself', () => {
    const view = renderScoped(
      <SettingField field={pem} {...binding({ error: 'no PEM block found' })} />,
    )

    expect(view.getByLabelText('Certificate')).toBeInvalid()
    expect(view.getByText('no PEM block found')).toBeInTheDocument()
  })
})

describe('a multi-line secret', () => {
  const key = field({
    key: 'tls.privateKey',
    kind: 'secretText',
    secret: true,
    viewKey: 'hasPrivateKey',
    label: 'Private key',
  })

  // The stored key is never sent back, so the box can only say whether there is one; a
  // box that read "not set" beside a working certificate would invite a needless paste.
  it.each([
    [true, 'stored — paste to replace'],
    [false, 'not set'],
  ])('reports stored=%s without ever showing the value', (stored, expected) => {
    const view = renderScoped(<SettingField field={key} {...binding({ stored })} />)

    const box = view.getByLabelText('Private key')
    expect(box.tagName).toBe('TEXTAREA')
    expect(box).toHaveAttribute('placeholder', expected)
    expect(box).toHaveValue('')
  })

  it('hands over what is pasted, newlines and all', () => {
    const onChange = vi.fn()
    const view = renderScoped(<SettingField field={key} {...binding({ stored: true, onChange })} />)

    fireEvent.change(view.getByLabelText('Private key'), { target: { value: 'k1\nk2' } })
    expect(onChange).toHaveBeenCalledWith('k1\nk2')
  })
})

describe('a stored choice the picker has no option for', () => {
  const scope = field({
    key: 'proxy.scope',
    kind: 'enum',
    label: 'Proxy scope',
    options: [{ value: 'tailnet', label: 'Tailnet only' }],
  })

  // The synthetic option is the stored value shown as itself, ahead of the real choices,
  // so the picker reports what is in force and a save writes nothing the reader did not
  // pick. An empty stored value is shown as absent rather than as a blank row.
  it('is listed first, as itself, ahead of the real choices', () => {
    const view = renderScoped(<SettingField field={scope} {...binding({ value: 'exitNode' })} />)

    const picker = view.getByLabelText('Proxy scope')
    expect(
      Array.from(picker.querySelectorAll('option')).map((o) => [o.value, o.textContent]),
    ).toEqual([
      ['exitNode', 'exitNode'],
      ['tailnet', 'Tailnet only'],
    ])
  })

  it('reads as absent when nothing is stored', () => {
    const view = renderScoped(<SettingField field={scope} {...binding({ value: '' })} />)

    const picker = view.getByLabelText('Proxy scope')
    expect(picker).toHaveValue('')
    expect(picker.querySelector('option[value=""]')).toHaveTextContent('—')
  })

  it('is not added when the stored value is one of the choices', () => {
    const view = renderScoped(<SettingField field={scope} {...binding({ value: 'tailnet' })} />)

    expect(view.getByLabelText('Proxy scope').querySelectorAll('option')).toHaveLength(1)
  })
})

describe('a rejected set of connections', () => {
  const members = field({
    key: 'egress.multi.tunnelIds',
    kind: 'tunnelRefList',
    label: 'Connections sharing it',
    options: [{ value: 'tn_office', label: 'Office' }],
  })

  // A group of boxes carries no aria-invalid of its own, so the message under it is the
  // only way a screen reader hears that the set was refused.
  it('points the group at the message under it', () => {
    const view = renderScoped(
      <SettingField field={members} {...binding({ value: 'tn_office', error: 'pick at least two' })} />,
    )

    const group = view.getByRole('group', { name: 'Connections sharing it' })
    expect(group).toHaveAccessibleDescription('pick at least two')
  })

  it('describes nothing when the set was accepted', () => {
    const view = renderScoped(<SettingField field={members} {...binding({ value: 'tn_office' })} />)

    expect(view.getByRole('group', { name: 'Connections sharing it' })).not.toHaveAttribute(
      'aria-describedby',
    )
  })
})
