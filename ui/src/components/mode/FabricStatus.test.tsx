// SPDX-License-Identifier: MIT

import { describe, expect, it } from 'vitest'

import { FabricStatus } from './FabricStatus'
import { makeFabric, renderScoped } from '../../test/agent'

// The panel's two states before it has anything to describe. What it is carrying, once it
// knows, is covered where the mode page renders it.
describe('what the interface carries, before it has an answer', () => {
  // Rendering the empty view instead would name the interface "—", give it no packet size
  // and report zero ranges, which is exactly what the page says when the mode is genuinely
  // broken. A reader cannot tell "not read yet" from "not working" out of that.
  it('says it is still reading rather than describing an interface it has not heard about', () => {
    const view = renderScoped(<FabricStatus view={undefined} chosen />)

    const panel = view.getByRole('region', { name: 'What the interface carries' })
    expect(panel).not.toHaveTextContent('not carrying')
    expect(panel).toHaveTextContent(/Reading what the interface is carrying/)
  })

  // A request that failed says why. Falling back to the reading-it message would leave the
  // panel waiting forever on an answer that is never coming.
  it('says why it could not be read', () => {
    const view = renderScoped(<FabricStatus view={undefined} chosen error="the agent is not answering" />)

    const panel = view.getByRole('region', { name: 'What the interface carries' })
    expect(panel).toHaveTextContent('the agent is not answering')
  })

  // The panel is about the mode, so under every other arrangement it is absent rather than
  // reporting an interface nobody asked for.
  it('is absent under every other arrangement', () => {
    const view = renderScoped(<FabricStatus view={makeFabric({ running: true })} chosen={false} />)

    expect(view.queryByRole('region', { name: 'What the interface carries' })).toBeNull()
  })
})
