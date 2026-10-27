// SPDX-License-Identifier: MIT

import { describe, expect, it } from 'vitest'

import { parseRoute, SECTIONS } from '../../lib/router'
import { HEROES, heroNamed } from './heroes'

describe('the dashboard heroes', () => {
  // A gear is the one way from a hero to the rest of its feature. One pointing at an
  // address nothing answers is a dead end that only shows up when somebody clicks it.
  it('each point at a page that exists', () => {
    for (const hero of HEROES) {
      const route = parseRoute(hero.route)
      expect(route.section).not.toBe('missing')
      expect(SECTIONS).toContain(route.section)
    }
  })

  it('never send two heroes to one page, or give two the same name', () => {
    const routes = HEROES.map((h) => h.route)
    const labels = HEROES.map((h) => h.label)

    expect(new Set(routes).size).toBe(routes.length)
    expect(new Set(labels).size).toBe(labels.length)
  })

  it('are found by id, and a wrong id is refused', () => {
    expect(heroNamed('internet').label).toBe('Internet')
    expect(() => heroNamed('mode')).toThrow('no hero is called mode')
  })
})
