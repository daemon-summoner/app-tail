// SPDX-License-Identifier: MIT

// The body of a card whose module is switched off.
//
// Off is not a fault. Every card is on the page whether or not its feature is on -- a
// feature reachable only once it is already on is one nobody finds -- so the off state
// needs a shape of its own. Without one, a card renders its module's capability reason
// as an error and an install that has simply not turned the feature on reads as broken.

export function ModuleOff({ children }: { children: string }) {
  return <p className="module-off">{children}</p>
}
