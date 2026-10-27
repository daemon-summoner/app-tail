// SPDX-License-Identifier: MIT

import { describe, expect, it } from 'vitest'

import type { FeatureModuleInfo, SettingFieldSchema } from '../../api'
import {
  availableFields,
  draftFrom,
  draftValueOf,
  exampleFor,
  fieldReason,
  fieldsInGroup,
  isPatchable,
  moduleIsOn,
  patchFrom,
  secretIsStored,
  type Draft,
  type SettingsView,
} from './fieldState'

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

const MODULES: FeatureModuleInfo[] = [
  {
    id: 'advancedNetworking',
    label: 'Advanced networking',
    description: '',
    switchKey: 'advancedNetworking',
  },
]

const SWITCH = field({ key: 'advancedNetworking', kind: 'bool', moduleSwitch: 'advancedNetworking' })
const OWNED = field({ key: 'controlURL', kind: 'url', module: 'advancedNetworking' })

describe('reading a field out of the settings document', () => {
  // A list is edited as one comma-separated string. Joining without the space, or not
  // joining at all, puts "[object Object]" or "tag:a,tag:b" in front of the user and
  // then sends whatever they leave behind.
  it('joins a list into the string the control edits', () => {
    const f = field({ key: 'tags', kind: 'stringList' })
    expect(draftValueOf(f, { tags: ['tag:a', 'tag:b'] })).toBe('tag:a, tag:b')
  })

  // A number input's value must be a string or React drops back to an uncontrolled
  // input, and the field silently stops reflecting the document.
  it('renders a number as the string its input holds', () => {
    const f = field({ key: 'udpBufferBytes', kind: 'int' })
    expect(draftValueOf(f, { udpBufferBytes: 65535 })).toBe('65535')
  })

  // The agent never sends a stored secret, so an empty box is the only honest start.
  // Seeding it from the view would put the literal `true` of `hasAuthKey` in the box
  // and save it as the new key.
  it('starts a secret empty regardless of what the view says about it', () => {
    const f = field({ key: 'authKey', kind: 'secret', secret: true, viewKey: 'hasAuthKey' })
    expect(draftValueOf(f, { hasAuthKey: true })).toBe('')
  })

  it('reads a boolean as a boolean and everything else as a string', () => {
    expect(draftValueOf(field({ key: 'ephemeral', kind: 'bool' }), { ephemeral: true })).toBe(true)
    expect(draftValueOf(field({ key: 'hostname' }), { hostname: 'box' })).toBe('box')
  })

  // A field the document does not carry -- an agent older than this page, or a key
  // renamed on one side only -- must render empty, not the string "undefined".
  it.each([
    ['bool', false],
    ['int', ''],
    ['stringList', ''],
    ['string', ''],
  ])('falls back to the empty %s when the document has no value', (kind, want) => {
    expect(draftValueOf(field({ key: 'missing', kind: kind as 'string' }), {})).toBe(want)
  })

  it('builds a draft entry for every field, read-only ones included', () => {
    const schema = [field({ key: 'hostname' }), field({ key: 'stateDir', write: 'none', readOnly: true })]
    expect(draftFrom(schema, { hostname: 'box', stateDir: '/tmp/state' })).toEqual({
      hostname: 'box',
      stateDir: '/tmp/state',
    })
  })

  it('reports a stored secret from the presence key alone', () => {
    const f = field({ key: 'authKey', kind: 'secret', secret: true, viewKey: 'hasAuthKey' })
    expect(secretIsStored(f, { hasAuthKey: true })).toBe(true)
    expect(secretIsStored(f, { hasAuthKey: false })).toBe(false)
  })
})

describe('the greyed sample an empty control shows', () => {
  const live = field({ key: 'hostname', example: 'a-name', exampleFrom: 'effectiveHostname' })

  // An empty device name is really the rendered template. Showing a generic sample
  // there would hide the only place the name actually in use appears.
  it('prefers the live value the setting stands in for', () => {
    expect(exampleFor(live, { effectiveHostname: 'app-tail-box' })).toBe('app-tail-box')
  })

  const missing: [string, SettingsView][] = [
    ['absent', {}],
    ['empty', { effectiveHostname: '' }],
    ['not a string', { effectiveHostname: 42 }],
  ]
  it.each(missing)('falls back to the static example when the live value is %s', (_name, view) => {
    expect(exampleFor(live, view)).toBe('a-name')
  })

  it('shows nothing for a field with neither', () => {
    expect(exampleFor(field({ key: 'hostname' }), {})).toBe('')
  })
})

describe('which settings this configuration can write', () => {
  const schema = [SWITCH, OWNED]

  it('hides a module’s settings while its switch is off in the draft', () => {
    const draft: Draft = { advancedNetworking: false, controlURL: '' }
    expect(availableFields(schema, MODULES, draft, draft).map((f) => f.key)).toEqual([
      'advancedNetworking',
    ])
  })

  it('reveals them the moment the draft turns the switch on', () => {
    const stored: Draft = { advancedNetworking: false, controlURL: '' }
    const draft: Draft = { advancedNetworking: true, controlURL: '' }
    expect(availableFields(schema, MODULES, draft, stored).map((f) => f.key)).toEqual([
      'advancedNetworking',
      'controlURL',
    ])
  })

  // The agent resolved availability against the stored document, where the module was
  // off. Honouring that answer would leave the just-revealed field hidden and the
  // switch looking broken.
  it('ignores a stale unavailable answer for a module the draft just turned on', () => {
    const stored: Draft = { advancedNetworking: false, controlURL: '' }
    const draft: Draft = { advancedNetworking: true, controlURL: '' }
    const served = [SWITCH, { ...OWNED, available: false, availableReason: 'module is off' }]
    expect(availableFields(served, MODULES, draft, stored).map((f) => f.key)).toContain('controlURL')
  })

  // With the module in the same position it was stored in, the agent knows reasons
  // this page does not -- an unsupported platform, a missing dependency. Offering the
  // control anyway produces a save the agent refuses in full.
  it('honours an unavailable answer for a module the draft has not moved', () => {
    const draft: Draft = { advancedNetworking: true, controlURL: '' }
    const served = [SWITCH, { ...OWNED, available: false, availableReason: 'not on this platform' }]
    expect(availableFields(served, MODULES, draft, draft).map((f) => f.key)).toEqual([
      'advancedNetworking',
    ])
  })

  // A module no switch governs can never be turned on, so its settings can never be
  // saved. Showing them would be a control that silently does nothing.
  it('fails closed for a module no switch in this form governs', () => {
    const orphan = field({ key: 'orphan', module: 'exitNode' })
    expect(moduleIsOn(orphan, MODULES, {})).toBe(false)
    expect(availableFields([orphan], MODULES, {}, {})).toEqual([])
  })

  // A connection form carries no module switches at all -- a module is the
  // installation's, not one network's -- so there is nothing here to resolve the gate
  // against. Failing closed would hide every module-gated field a connection has, which
  // is most of what a tailnet connection is configured with.
  it('leaves the gate to the agent for a form that carries no switches', () => {
    const gated = field({ key: 'routes.accept', kind: 'bool', module: 'routing' })
    expect(moduleIsOn(gated, [], {})).toBe(true)
    expect(availableFields([gated], [], {}, {}).map((f) => f.key)).toEqual(['routes.accept'])
  })

  // The other half of the same rule: with no switch to consult, the agent's answer is
  // the only one, so a field it called unavailable stays hidden.
  it('honours the agent’s refusal for a form that carries no switches', () => {
    const gated = field({ key: 'routes.accept', kind: 'bool', module: 'routing' })
    const off = { ...gated, available: false, availableReason: 'the module is off' }
    expect(availableFields([off], [], {}, {})).toEqual([])
  })

  // The real shape of this: proxy.system belongs to the proxy module and exists on
  // Windows alone. Turning the proxy on from a Mac must not reveal it -- the agent
  // refuses that key by name, and it refuses the whole save with it.
  it('keeps a setting this machine does not have hidden when the draft turns its module on', () => {
    const stored: Draft = { advancedNetworking: false, controlURL: '' }
    const draft: Draft = { advancedNetworking: true, controlURL: '' }
    const served = [
      SWITCH,
      { ...OWNED, available: false, platformSupported: false, availableReason: 'not on macOS' },
    ]
    expect(availableFields(served, MODULES, draft, stored).map((f) => f.key)).toEqual([
      'advancedNetworking',
    ])
  })

  it('treats a core setting as always available', () => {
    expect(moduleIsOn(field({ key: 'hostname' }), [], {})).toBe(true)
  })
})

describe('the fields a section renders', () => {
  const schema = [
    field({ key: 'hostname', group: 'identity', tier: 'basic' }),
    field({ key: 'hostnameTemplate', group: 'identity', tier: 'advanced' }),
    field({ key: 'showTray', group: 'application', tier: 'basic' }),
  ]

  it('keeps the advanced tier out of the way until it is asked for', () => {
    expect(fieldsInGroup(schema, 'identity', false).map((f) => f.key)).toEqual(['hostname'])
    expect(fieldsInGroup(schema, 'identity', true).map((f) => f.key)).toEqual([
      'hostname',
      'hostnameTemplate',
    ])
  })

  it('never leaks a field into another section', () => {
    expect(fieldsInGroup(schema, 'application', true).map((f) => f.key)).toEqual(['showTray'])
  })

  it('marks only patchable settings as patchable', () => {
    expect(isPatchable(field({ key: 'hostname' }))).toBe(true)
    expect(isPatchable(field({ key: 'startAtLogin', write: 'autostart' }))).toBe(false)
    expect(isPatchable(field({ key: 'stateDir', write: 'none', readOnly: true }))).toBe(false)
    // A derived value is served through the patch's write path but can never be set.
    expect(isPatchable(field({ key: 'effectiveHostname', readOnly: true }))).toBe(false)
  })
})

describe('the patch a save carries', () => {
  const schema = [
    field({ key: 'hostname' }),
    field({ key: 'tags', kind: 'stringList' }),
    field({ key: 'udpBufferBytes', kind: 'int' }),
    field({ key: 'authKey', kind: 'secret', secret: true, viewKey: 'hasAuthKey' }),
    field({ key: 'stateDir', write: 'none', readOnly: true }),
    field({ key: 'startAtLogin', kind: 'bool', write: 'autostart' }),
    SWITCH,
    OWNED,
  ]
  const stored: Draft = {
    hostname: 'box',
    tags: 'tag:a, tag:b',
    udpBufferBytes: '65535',
    authKey: '',
    stateDir: '/tmp/state',
    startAtLogin: false,
    advancedNetworking: false,
    controlURL: '',
  }

  // Sending every field lets a stale form overwrite a change the CLI or the tray made
  // to a setting the user never looked at, with no error anywhere.
  it('is empty when nothing was edited', () => {
    expect(patchFrom(schema, MODULES, stored, stored)).toEqual({})
  })

  it('carries only what moved', () => {
    const draft = { ...stored, hostname: 'other-box' }
    expect(patchFrom(schema, MODULES, draft, stored)).toEqual({ hostname: 'other-box' })
  })

  it('converts each kind to the shape the agent decodes', () => {
    const draft = { ...stored, tags: ' tag:c ,, tag:d ', udpBufferBytes: '2048' }
    expect(patchFrom(schema, MODULES, draft, stored)).toEqual({
      tags: ['tag:c', 'tag:d'],
      udpBufferBytes: 2048,
    })
  })

  // Re-typing the same list in a different order is a real change; treating the two as
  // equal would silently drop an edit the user made and watched take effect on screen.
  it('notices a reordered list but not a re-typed identical one', () => {
    expect(patchFrom(schema, MODULES, { ...stored, tags: 'tag:a, tag:b' }, stored)).toEqual({})
    expect(patchFrom(schema, MODULES, { ...stored, tags: 'tag:b, tag:a' }, stored)).toEqual({
      tags: ['tag:b', 'tag:a'],
    })
  })

  // A present-but-empty secret reads to the agent as "clear it", which deletes a
  // stored auth key and breaks the next unattended enrollment.
  it('omits an untouched secret and sends a typed one', () => {
    expect(patchFrom(schema, MODULES, stored, stored)).not.toHaveProperty('authKey')
    expect(patchFrom(schema, MODULES, { ...stored, authKey: 'tskey-new' }, stored)).toEqual({
      authKey: 'tskey-new',
    })
  })

  it('never carries a read-only fact or a setting with its own endpoint', () => {
    const draft = { ...stored, stateDir: '/elsewhere', startAtLogin: true }
    expect(patchFrom(schema, MODULES, draft, stored)).toEqual({})
  })

  // The agent refuses a setting whose module is off and refuses the whole save with
  // it. Switching a module off is exactly when its old values are still in the draft.
  it('drops a module’s settings from the same save that switches it off', () => {
    const on: Draft = { ...stored, advancedNetworking: true, controlURL: 'https://hs.example.com' }
    const off: Draft = { ...on, advancedNetworking: false }
    expect(patchFrom(schema, MODULES, off, on)).toEqual({ advancedNetworking: false })
  })

  it('carries a module’s switch and the setting it reveals together', () => {
    const draft: Draft = {
      ...stored,
      advancedNetworking: true,
      controlURL: 'https://hs.example.com',
    }
    expect(patchFrom(schema, MODULES, draft, stored)).toEqual({
      advancedNetworking: true,
      controlURL: 'https://hs.example.com',
    })
  })
})

describe('the reason a control shows for a rejected save', () => {
  it('drops the key the agent prefixed, since the label is already beside it', () => {
    expect(fieldReason('uiListenAddr: must be a loopback address', 'uiListenAddr')).toBe(
      'must be a loopback address',
    )
  })

  // A message about a different field, or one with no prefix, must survive whole --
  // trimming it on a guess would hand the user half a sentence.
  it('leaves a message it cannot attribute alone', () => {
    expect(fieldReason('could not parse JSON body', 'uiListenAddr')).toBe(
      'could not parse JSON body',
    )
    expect(fieldReason('tags: must start with tag:', 'uiListenAddr')).toBe(
      'tags: must start with tag:',
    )
  })
})
