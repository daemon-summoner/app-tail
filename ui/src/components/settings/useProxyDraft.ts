// SPDX-License-Identifier: MIT

// One proxy instance's form: the shared draft machinery pointed at the instance
// endpoints.
//
// It is a handful of lines for the reason the connection form is: an instance is rendered
// and written by exactly the code the settings document is. Its permissions are not here
// -- a rule is a tuple matched in order rather than a field with a value, so the rules
// table is written by hand and saved through its own endpoint.

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
 * useProxyDraft is the form for the proxy instance with this id.
 *
 * `gates` are the installation's module switches, keyed the way the settings document keys
 * them: most of an instance's fields are gated on the proxy module, which the instance
 * itself does not hold, so without the live values turning the module on here would reveal
 * nothing until the page was reloaded.
 *
 * `generation` is how a caller says the instance was written from somewhere other than this
 * form -- saving its rules answers with the whole instance, which moves the derived reading
 * of those rules. Changing it reads the instance again.
 */
export function useProxyDraft(id: string, gates: Draft = {}, generation = 0): EntityDraft {
  const source = useMemo<EntitySource>(
    () => ({
      load: async (): Promise<EntityLoad> => {
        const [served, held] = await Promise.all([api.proxySchema(), api.proxies()])
        const instance = held.find((p) => p.id === id)
        if (instance === undefined) {
          // Loudly, because the alternative is an empty form that reads as an instance with
          // nothing configured rather than one that is not there.
          throw new Error(`there is no proxy ${id}`)
        }
        return {
          fields: served.fields,
          groups: served.groups,
          modules: served.modules,
          view: instance.settings,
        }
      },
      save: async (patch: Record<string, unknown>): Promise<EntitySaved> => {
        const updated = await api.updateProxy(id, patch)
        return { view: updated.settings }
      },
    }),
    // generation is a reload signal rather than a value the load reads, which is exactly
    // why it belongs here: rebuilding the source is what reads the instance again.
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [id, generation],
  )

  return useEntityDraft(source, gates)
}
