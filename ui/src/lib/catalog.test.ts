// SPDX-License-Identifier: MIT

import { describe, expect, it } from 'vitest'

import { groupByProvider } from './catalog'
import type { DNSBlockListView } from '../api'

function list(id: string, provider: string): DNSBlockListView {
  return {
    id,
    provider,
    name: id,
    url: `https://lists.example.test/${id}.txt`,
    builtIn: true,
    enabled: false,
    rules: 0,
    skipped: 0,
  }
}

describe('grouping the catalog by who publishes it', () => {
  // The agent sends the catalog in a curated order -- tiers before topic lists before
  // threat feeds -- and the picker offers it in that order. Re-sorting here would move the
  // everyday tier away from the top of its group.
  it('keeps providers and their lists in the order they arrived', () => {
    const groups = groupByProvider([
      list('hagezi-pro', 'Hagezi'),
      list('hagezi-tif', 'Hagezi'),
      list('oisd-small', 'OISD'),
    ])

    expect(groups.map((g) => g.provider)).toEqual(['Hagezi', 'OISD'])
    expect(groups[0]!.items.map((l) => l.id)).toEqual(['hagezi-pro', 'hagezi-tif'])
    expect(groups[1]!.items.map((l) => l.id)).toEqual(['oisd-small'])
  })

  // One provider heading is the point of grouping. A set that arrives interleaved would
  // otherwise print the same heading twice, which reads as two different publishers.
  it('collects lists of one provider that did not arrive together', () => {
    const groups = groupByProvider([
      list('hagezi-pro', 'Hagezi'),
      list('work', 'Your lists'),
      list('hagezi-tif', 'Hagezi'),
    ])

    expect(groups.map((g) => g.provider)).toEqual(['Hagezi', 'Your lists'])
    expect(groups[0]!.items.map((l) => l.id)).toEqual(['hagezi-pro', 'hagezi-tif'])
  })

  it('groups nothing into nothing', () => {
    expect(groupByProvider([])).toEqual([])
  })
})
