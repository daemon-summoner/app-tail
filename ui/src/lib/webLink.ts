// SPDX-License-Identifier: MIT

/** webLink is address when following it opens a web page, and undefined otherwise. An
 *  address another machine chose can name a script or another program as easily as a page,
 *  and a link runs whatever its scheme says, so only http and https are let through. */
export function webLink(address: string | undefined): string | undefined {
  if (address === undefined || !URL.canParse(address)) return undefined
  const { protocol } = new URL(address)
  return protocol === 'http:' || protocol === 'https:' ? address : undefined
}
