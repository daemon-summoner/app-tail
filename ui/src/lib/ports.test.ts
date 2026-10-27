// SPDX-License-Identifier: MIT

import { describe, expect, it } from 'vitest'

import { isPort, parsePortSpec, splitHostPort } from './ports'

// parsePortSpec is what stands between a typo in the add-forward dialog and a batch
// of forwards nobody asked for, so every rejection path is worth pinning.
describe('parsePortSpec', () => {
  it('expands, sorts, and de-duplicates a mixed spec', () => {
    expect(parsePortSpec('9002, 9000-9002, 8100')).toEqual({ ports: [8100, 9000, 9001, 9002] })
  })

  it('treats an empty spec as nothing typed yet, not as junk', () => {
    // The dialog relies on this to tell a blank field from an invalid one.
    expect(parsePortSpec('')).toEqual({ ports: [] })
    expect(parsePortSpec('   ')).toEqual({ ports: [] })
  })

  it('accepts whitespace as a separator', () => {
    expect(parsePortSpec('22 80\t443')).toEqual({ ports: [22, 80, 443] })
  })

  it.each([
    ['a port above the range', '65536', 'not a valid port'],
    ['zero', '0', 'not a valid port'],
    ['a range endpoint out of bounds', '1-65536', 'not a valid range'],
    ['a backwards range', '9005-9000', 'backwards'],
    ['a non-numeric token', 'http', 'not a port or range'],
    ['a negative number, which the range regex must not eat', '-5', 'not a port or range'],
  ])('rejects %s', (_label, spec, fragment) => {
    const result = parsePortSpec(spec)
    expect(result.ports).toEqual([])
    expect(result.error).toContain(fragment)
  })

  // The cap is the whole reason a fat-fingered "1-65535" cannot spawn a fleet of
  // forwards, so both the accepted edge and the first rejected one are pinned.
  it('accepts exactly the cap and rejects one more', () => {
    expect(parsePortSpec('1-128').ports).toHaveLength(128)
    const tooMany = parsePortSpec('1-129')
    expect(tooMany.ports).toEqual([])
    expect(tooMany.error).toContain('more than 128 ports')
  })

  // Duplicates must not count toward the cap, or a spec well under it gets refused.
  it('counts unique ports against the cap, not tokens', () => {
    expect(parsePortSpec('1-128, 1-128').ports).toHaveLength(128)
  })

  // Every rejection returns an empty list, so one bad token discards the whole spec
  // rather than quietly creating forwards for the good half -- a partial batch the
  // user never asked for is worse than a refusal they can see.
  it('rejects the whole spec when one token in it is bad', () => {
    const result = parsePortSpec('8080, http, 9000')
    expect(result.ports).toEqual([])
    expect(result.error).toContain('"http"')
  })

  it('accepts a range whose ends are the same port', () => {
    expect(parsePortSpec('8080-8080')).toEqual({ ports: [8080] })
  })

  // Number() would happily read both of these, so the digits-only guard is the only
  // thing between "0x50" and a forward on port 80 the user never typed.
  it.each([
    ['a hexadecimal literal', '0x50'],
    ['an explicitly signed number', '+80'],
    ['a decimal port', '80.0'],
    ['exponent notation', '8e1'],
    ['a range with a signed endpoint', '+80-90'],
  ])('rejects %s rather than coercing it', (_label, spec) => {
    const result = parsePortSpec(spec)
    expect(result.ports).toEqual([])
    expect(result.error).toContain('not a port or range')
  })
})

describe('isPort', () => {
  it.each([
    [1, true],
    [65535, true],
    [0, false],
    [65536, false],
    [8080.5, false],
    [NaN, false],
  ])('isPort(%s) is %s', (n, want) => {
    expect(isPort(n)).toBe(want)
  })
})

describe('splitHostPort', () => {
  it('splits a host and port', () => {
    expect(splitHostPort('10.0.0.4:5432')).toEqual({ host: '10.0.0.4', port: 5432 })
  })

  // Splitting on the first colon would turn "[::1]:22" into host "[" — the reason
  // this uses lastIndexOf.
  it('keeps an IPv6 literal intact', () => {
    expect(splitHostPort('[fd7a::1]:22')).toEqual({ host: '[fd7a::1]', port: 22 })
  })

  it('reports a missing port as NaN rather than guessing one', () => {
    const { host, port } = splitHostPort('db.internal')
    expect(host).toBe('db.internal')
    expect(port).toBeNaN()
  })

  // Number('') is 0, not NaN, so a trailing colon produces a port that is a real
  // number. Only isPort(0) === false keeps "db.internal:" from being read as a
  // valid target, which is why the two functions are pinned together here.
  it('yields a port of zero, not NaN, for a bare trailing colon', () => {
    const { host, port } = splitHostPort('db.internal:')
    expect(host).toBe('db.internal')
    expect(port).toBe(0)
    expect(isPort(port)).toBe(false)
  })
})
