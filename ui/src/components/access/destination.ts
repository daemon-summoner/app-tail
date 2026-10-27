// SPDX-License-Identifier: MIT

// The one box a rule's destination is written in, and what it turns into.
//
// A rule carries two separate destination fields: a name matched against what a program
// asked for, and a range matched against what that name resolved to. Asking for both would
// put the hardest distinction in the model in front of somebody adding their first rule --
// so the editor takes one value and works out which field it is, exactly the way a person
// reading it would.
//
// The classification is for the editor only. The agent validates what it is sent and is the
// authority on what a rule may carry; nothing here decides whether a rule is legal.

import type { AccessRule } from '../../api'

/** The two destination fields, which is all these readers need of a rule. Naming the shape
 *  rather than one rule type is what lets the routing rules reuse them: their destination is
 *  written the same way and read by the same person. */
interface Destinated {
  host?: string | undefined
  cidr?: string | undefined
}

/** Which field a written destination lands in. `anywhere` is the empty box, which is a
 *  real answer: a rule with no destination matches every destination. */
export type DestinationKind = 'anywhere' | 'host' | 'range'

export interface Destination {
  kind: DestinationKind
  /** What goes on the rule. Exactly one of these is set, and neither is when the box is
   *  empty. */
  host?: string
  cidr?: string
}

/** The chip shown under the box, so somebody typing 10.0.0.0/8 can see it was read as a
 *  range and somebody typing db.* can see it was read as a name. */
export function describeDestination(kind: DestinationKind): string {
  switch (kind) {
    case 'anywhere':
      return 'anywhere — this rule matches every destination'
    case 'range':
      return 'a range of addresses, matched against what a name resolves to'
    default:
      return 'a name, matched against what a program asked for'
  }
}

const IPV4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/

function isIPv4(text: string): boolean {
  const parts = IPV4.exec(text)
  if (parts === null) return false
  return parts.slice(1).every((part) => {
    const n = Number(part)
    // Leading zeros are rejected the way the agent's parser rejects them, so a box that
    // reads 010.0.0.1 as a name and an agent that refuses it as an address do not disagree.
    return part === String(n) && n >= 0 && n <= 255
  })
}

function isIPv6(text: string): boolean {
  return text.includes(':') && /^[0-9A-Fa-f:.]+$/.test(text)
}

/**
 * classifyDestination reads one written destination.
 *
 * A bare address becomes a range holding only itself rather than a name, because a name is
 * matched before resolution and an address never goes through that step -- a rule carrying
 * 10.0.0.5 as a host would match nothing at all.
 */
export function classifyDestination(written: string): Destination {
  const text = written.trim()
  if (text === '') return { kind: 'anywhere' }
  if (text.includes('/')) return { kind: 'range', cidr: text }
  if (isIPv4(text)) return { kind: 'range', cidr: `${text}/32` }
  if (isIPv6(text)) return { kind: 'range', cidr: `${text}/128` }
  return { kind: 'host', host: text }
}

/** What the box shows for a stored rule. A rule carrying both a name and a range is the
 *  one shape this box cannot hold, so it shows the name and the range is reported beside
 *  it rather than silently dropped -- see `extraDestination`. */
export function destinationOf(rule: Destinated): string {
  if (rule.host !== undefined && rule.host !== '') return rule.host
  return rule.cidr ?? ''
}

/** The half of a two-part destination the box is not showing, or undefined when there is
 *  none. Editing such a rule in this table would otherwise quietly widen it. */
export function extraDestination(rule: Destinated): string | undefined {
  const host = rule.host ?? ''
  const cidr = rule.cidr ?? ''
  return host !== '' && cidr !== '' ? cidr : undefined
}

/** The ports box, which takes the list a rule stores as one line. An empty line is every
 *  port; the agent refuses an empty list, so nothing here can produce one. */
export function portsFrom(written: string): string[] | undefined {
  const parts = written
    .split(',')
    .map((p) => p.trim())
    .filter((p) => p !== '')
  return parts.length === 0 ? undefined : parts
}

export function portsOf(rule: AccessRule): string {
  return (rule.ports ?? []).join(', ')
}
