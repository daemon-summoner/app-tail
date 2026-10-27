// SPDX-License-Identifier: MIT

// Every card on the dashboard, in one shape.
//
// The head is fixed in order -- name, what it always does, what it is doing now, its
// switch, then anything it can be told to do -- so the eye lands in the same place on
// every card and a card that has nothing to say in a slot simply leaves a gap.

import type { ReactNode } from 'react'
import { InfoPopover } from './InfoPopover'

interface PanelStatus {
  /** tone is the colour class: running, pending, error or off. */
  tone: string
  /** label is the word beside the dot. State is never carried by hue alone, so this
   *  is not optional. */
  label: string
  /** detail is what the state is true of -- an address, an interface name -- set in
   *  monospace beside the word. */
  detail?: string | undefined
}

interface PanelProps {
  title: string
  /** regionLabel names the region when the heading is not the right name for it. Only
   *  Forwards needs it: its heading is one word and the region it answers to is two,
   *  because the mode strip already carries the longer name. */
  regionLabel?: string | undefined
  /** id is an anchor target, for the mode strip to scroll to. */
  id?: string | undefined
  status?: PanelStatus | undefined
  /** info is what this card always does, behind the head's info button. */
  info?: ReactNode | undefined
  /** controls is the module switch, which sits with the name rather than in the body:
   *  a card that is off has no body to put it in. */
  controls?: ReactNode | undefined
  /** actions are the buttons this card offers, right-aligned. */
  actions?: ReactNode | undefined
  /** wide spans the card deck's full width, for a card whose body has columns of its
   *  own to lay out. */
  wide?: boolean | undefined
  /** bare drops the padded body, for a card whose content reaches the card's own edges:
   *  a table's rules and the connection row both run the full width. */
  bare?: boolean | undefined
  /** primary marks the one card a page is about, which carries the accent down its
   *  edge so the eye lands there first. One per page, or it marks nothing. */
  primary?: boolean | undefined
  children?: ReactNode | undefined
}

export function Panel({
  title,
  regionLabel,
  id,
  status,
  info,
  controls,
  actions,
  wide,
  bare,
  primary,
  children,
}: PanelProps) {
  const className = ['panel', wide ? 'wide' : '', primary ? 'primary' : ''].join(' ').trim()
  return (
    // A section is a landmark only once it has a name, and every card is one.
    <section className={className} id={id} aria-label={regionLabel ?? title}>
      <div className="panel-head">
        <h2>{title}</h2>
        {info ? <InfoPopover label={title}>{info}</InfoPopover> : null}
        {status ? <StatusChip status={status} /> : null}
        <span className="spacer" />
        {controls}
        {actions}
      </div>

      {children === undefined ? null : bare ? children : <div className="panel-body">{children}</div>}
    </section>
  )
}

/** StatusChip is the dot and the word. The dot is decorative -- the word is the state. */
function StatusChip({ status }: { status: PanelStatus }) {
  return (
    <span className={`status ${status.tone}`}>
      <span className="dot" aria-hidden="true" />
      {status.label}
      {status.detail ? <span className="mono"> {status.detail}</span> : null}
    </span>
  )
}
