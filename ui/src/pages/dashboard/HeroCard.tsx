// SPDX-License-Identifier: MIT

// One hero card: a Panel headed by its hero's name, with the gear to the feature's own
// page in the actions slot. The gear is not optional. A hero holds the one control
// somebody flips often and leaves the rest to its page, so a card without the gear would
// be a card whose remaining settings cannot be found from here.

import type { ReactNode } from 'react'

import { Panel } from '../../components/Panel'
import { GearIcon } from '../../components/shell/icons'
import type { Hero } from './heroes'

interface HeroStatus {
  tone: string
  label: string
  detail?: string | undefined
}

interface HeroCardProps {
  hero: Hero
  status?: HeroStatus | undefined
  info?: ReactNode | undefined
  /** controls is the hero's module switch, beside the name like every other card's. */
  controls?: ReactNode | undefined
  wide?: boolean | undefined
  children?: ReactNode | undefined
}

export function HeroCard({ hero, status, info, controls, wide, children }: HeroCardProps) {
  return (
    <Panel
      title={hero.label}
      status={status}
      info={info}
      controls={controls}
      wide={wide}
      actions={
        <a className="hero-gear" href={hero.route} aria-label={`${hero.label} settings`}>
          <GearIcon />
        </a>
      }
    >
      {children}
    </Panel>
  )
}
