// SPDX-License-Identifier: MIT

// Pure helpers for the add/edit-forward dialog: parsing a port spec into concrete
// ports and splitting a stored target back into host and port. Kept free of React
// and the API client so the logic can be exercised on its own.

// MAX_BATCH_PORTS caps how many forwards one port spec can create, so a fat-fingered
// "1-65535" cannot spawn tens of thousands of forwards.
const MAX_BATCH_PORTS = 128

export function isPort(n: number): boolean {
  return Number.isInteger(n) && n >= 1 && n <= 65535
}

/** parsePortSpec expands "8100, 9000-9005" into a sorted, de-duplicated port list,
 *  or returns a message naming what was wrong. An empty spec yields no ports and no
 *  error, so the caller can distinguish "nothing typed yet" from "typed junk". */
export function parsePortSpec(spec: string): { ports: number[]; error?: string } {
  const trimmed = spec.trim()
  if (trimmed === '') return { ports: [] }
  const seen = new Set<number>()
  const ports: number[] = []
  const add = (n: number): boolean => {
    if (!seen.has(n)) {
      seen.add(n)
      ports.push(n)
    }
    return ports.length <= MAX_BATCH_PORTS
  }
  for (const token of trimmed.split(/[\s,]+/).filter(Boolean)) {
    const range = token.match(/^(\d+)-(\d+)$/)
    if (range) {
      const lo = Number(range[1])
      const hi = Number(range[2])
      if (!isPort(lo) || !isPort(hi)) return { ports: [], error: `"${token}" is not a valid range (1-65535).` }
      if (lo > hi) return { ports: [], error: `Range "${token}" is backwards; put the lower port first.` }
      for (let p = lo; p <= hi; p++) {
        if (!add(p)) return { ports: [], error: `That is more than ${MAX_BATCH_PORTS} ports; narrow the range.` }
      }
      continue
    }
    if (/^\d+$/.test(token)) {
      const n = Number(token)
      if (!isPort(n)) return { ports: [], error: `"${token}" is not a valid port (1-65535).` }
      if (!add(n)) return { ports: [], error: `That is more than ${MAX_BATCH_PORTS} ports; shorten the list.` }
      continue
    }
    return { ports: [], error: `"${token}" is not a port or range. Try e.g. 8100, 9000-9005.` }
  }
  ports.sort((a, b) => a - b)
  return { ports }
}

/** splitHostPort separates a stored target into its host and port for editing,
 *  keeping an IPv6 literal's own colons intact. Port is NaN when absent. */
export function splitHostPort(target: string): { host: string; port: number } {
  const i = target.lastIndexOf(':')
  if (i < 0) return { host: target, port: NaN }
  return { host: target.slice(0, i), port: Number(target.slice(i + 1)) }
}
