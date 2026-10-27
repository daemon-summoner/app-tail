// SPDX-License-Identifier: MIT

// One connection's form: the shared draft machinery pointed at the connection
// endpoints.
//
// It is a handful of lines because nothing about a connection form is special. The schema
// says which fields this connection has and what each one accepts, the stored values
// arrive under the same keys, and a patch goes back the same way -- so a connection is
// rendered and written by exactly the code the settings document is.

import { useMemo } from 'react'
import { api } from '../../api'
import type { Draft } from './fieldState'
import {
  useEntityDraft,
  type EntityDraft,
  type EntityLoad,
  type EntitySaved,
  type EntitySource,
} from './useEntityDraft'

/**
 * useTunnelDraft is the form for the connection with this id.
 *
 * A connection's writes take effect where they are stored -- renaming one changes what it
 * is called and nothing else -- so none of the three "stored but not yet in force"
 * members an EntitySaved may carry are set here.
 *
 * `gates` are the installation's module switches, keyed the way the settings document
 * keys them. Several connection settings are gated on a module the connection does not
 * hold, so without the live values the form would show whatever was true when it loaded.
 *
 * `generation` is how a caller says the connection was rewritten from somewhere other than
 * this form -- importing a configuration file does that, replacing every field at once.
 * Changing it reads the connection again. It is not a poll: a form that reloaded on its own
 * would throw away whatever the reader had typed since.
 */
export function useTunnelDraft(id: string, gates: Draft = {}, generation = 0): EntityDraft {
  const source = useMemo<EntitySource>(
    () => ({
      load: async (): Promise<EntityLoad> => {
        const [served, tunnel] = await Promise.all([api.tunnelSchema(), api.tunnels()])
        const held = tunnel.find((t) => t.id === id)
        if (held === undefined) {
          // Loudly, because the alternative is an empty form that looks like a
          // connection with nothing configured rather than one that is not there.
          throw new Error(`there is no connection ${id}`)
        }
        // One schema describes every kind of connection, because the kinds a build can
        // bring up are its answer to give. Which of those fields this connection has is
        // decided here: a field carrying a variant belongs to that kind alone, and a
        // tailnet's enrollment settings on a WireGuard connection would be controls that
        // write somewhere the connection does not have.
        const fields = served.fields.filter(
          (f) => f.variant === undefined || f.variant === held.type,
        )
        return {
          fields,
          // A heading whose every field belongs to another kind is an empty section, which
          // reads as settings that failed to load rather than settings that are not there.
          groups: served.groups.filter((g) => fields.some((f) => f.group === g.id)),
          // The switches these fields are gated on belong to the installation rather than
          // to this connection, so their values arrive separately -- see `gates`.
          modules: served.modules,
          view: held.settings,
        }
      },
      save: async (patch: Record<string, unknown>): Promise<EntitySaved> => {
        const updated = await api.updateTunnel(id, patch)
        return { view: updated.settings }
      },
    }),
    // generation is a reload signal rather than a value the load reads, which is exactly
    // why it belongs here: rebuilding the source is what reads the connection again.
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [id, generation],
  )

  return useEntityDraft(source, gates)
}
