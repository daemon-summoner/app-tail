// SPDX-License-Identifier: MIT

/** One provider and the catalog entries it publishes. */
export interface ProviderGroup<T> {
  provider: string
  items: T[]
}

/** groupByProvider puts the entries of one provider together, providers in the order they
 *  first appear. The agent already sends a catalog that way, so the order the user is
 *  offered stays the curated one -- tiers before topic lists before threat feeds -- rather
 *  than being re-sorted alphabetically here.
 *
 *  It is written against the one field it reads, because both catalogs the app shows -- the
 *  lists of names and the feeds of addresses -- are grouped the same way and neither is
 *  served by a second copy of this. */
export function groupByProvider<T extends { provider: string }>(
  entries: readonly T[],
): ProviderGroup<T>[] {
  const groups: ProviderGroup<T>[] = []
  const byProvider = new Map<string, ProviderGroup<T>>()
  for (const entry of entries) {
    let group = byProvider.get(entry.provider)
    if (group === undefined) {
      group = { provider: entry.provider, items: [] }
      byProvider.set(entry.provider, group)
      groups.push(group)
    }
    group.items.push(entry)
  }
  return groups
}
