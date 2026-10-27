// SPDX-License-Identifier: MIT

import { RestartButton } from '../RestartButton'
import { RefreshIcon } from './icons'

/** TopBar names the page and holds the two things that apply to all of them: reading
 *  everything on screen again, and restarting the agent serving it. */
export function TopBar({
  title,
  version,
  onRefresh,
}: {
  title: string
  /** version is left out rather than rendered blank while the agent has not answered. */
  version: string | undefined
  onRefresh: () => void
}) {
  return (
    <header className="topbar">
      <svg className="wordmark" viewBox="0 0 32 32" aria-hidden="true">
        <rect className="plate" width="32" height="32" rx="7" />
        <circle className="node" cx="9" cy="10" r="2.6" />
        <circle className="node" cx="9" cy="22" r="2.6" />
        <circle className="node" cx="23" cy="16" r="2.6" />
        <path
          className="link"
          d="M11.4 11.2 20.6 15M11.4 20.8 20.6 17"
          fill="none"
          strokeWidth="1.8"
          strokeLinecap="round"
          opacity="0.55"
        />
      </svg>
      {/* The page's name is the heading, because the page is what the document is about;
          the app's name is beside the mark, where a brand belongs. */}
      <span className="brand">app-tail</span>
      <h1>{title}</h1>
      <span className="spacer" />
      {/* The chip is width-capped, so the full build string lives in the tooltip: a
          development version is a timestamp plus a commit plus a dirty marker. */}
      {version ? (
        <span className="version" title={version}>
          {version}
        </span>
      ) : null}
      <button className="btn small" onClick={onRefresh}>
        <RefreshIcon />
        Refresh
      </button>
      <RestartButton />
    </header>
  )
}
