// SPDX-License-Identifier: MIT

import { describe, expect, it } from 'vitest'

import { webLink } from './webLink'

describe('webLink', () => {
  it.each(['https://login.tailscale.com/a/abc', 'http://headscale.lan:8080/register/x'])(
    'keeps %s',
    (address) => {
      expect(webLink(address)).toBe(address)
    },
  )

  // Each of these does something other than open a page when followed.
  it.each([
    'javascript:alert(1)',
    ' javascript:alert(1)',
    'JaVaScRiPt:alert(1)',
    'java\tscript:alert(1)',
    'data:text/html,<script>alert(1)</script>',
    'vbscript:msgbox(1)',
    'file:///etc/passwd',
    'tailscale://login',
    '//login.tailscale.com/a/abc',
    'login.tailscale.com/a/abc',
    '/a/abc',
    '',
  ])('drops %j', (address) => {
    expect(webLink(address)).toBeUndefined()
  })

  it('has nothing to give for an address that is absent', () => {
    expect(webLink(undefined)).toBeUndefined()
  })
})
