// SPDX-License-Identifier: MIT

// The global settings form: the shared draft machinery pointed at the settings
// endpoints, plus the two things only this document has -- the login item, which is
// written through its own endpoint and has no draft behind it, and the node restart that
// puts a stored identity change into force.

import { useCallback, useMemo, useState } from 'react'
import { api, type AutostartView, type SettingFieldSchema } from '../../api'
import type { SettingsView } from './fieldState'
import {
  messageOf,
  useEntityDraft,
  type EntityDraft,
  type EntityLoad,
  type EntitySaved,
  type EntitySource,
  type FieldBinding,
} from './useEntityDraft'

export type { EntityForm, FieldBinding } from './useEntityDraft'

export interface SettingsForm extends EntityDraft {
  restarting: boolean
  restartNode: () => Promise<void>
}

export function useSettingsDraft(): SettingsForm {
  const [restarting, setRestarting] = useState(false)
  // The login item is the one setting with its own endpoint, so its live value comes
  // from there rather than from the settings document, which only records what the
  // agent last stored.
  const [autostart, setAutostart] = useState<boolean | undefined>(undefined)
  const [autostartError, setAutostartError] = useState<string | undefined>(undefined)

  // A login item can be installed and still be one that will not start app-tail -- wrong
  // rights for the network mode, or naming a binary that has moved. Nothing on the machine
  // says so until the next login, so the switch is where it has to be said, and every
  // answer from the endpoint carries the current verdict rather than only the first.
  const showAutostart = useCallback((view: AutostartView) => {
    setAutostart(view.enabled)
    setAutostartError(view.problem)
  }, [])

  const writeAutostart = useCallback(
    async (next: boolean) => {
      setAutostartError(undefined)
      try {
        showAutostart(await api.setAutostart(next))
      } catch (cause) {
        setAutostartError(messageOf(cause))
      }
    },
    [showAutostart],
  )

  const external = useCallback(
    (field: SettingFieldSchema): FieldBinding | undefined => {
      if (field.write !== 'autostart') return undefined
      return {
        value: autostart ?? false,
        example: '',
        onChange: (next) => void writeAutostart(next === true),
        stored: false,
        error: autostartError,
        // Until the endpoint answers, the switch has no state to show, and a guess the
        // user could click is worse than one they cannot.
        disabled: autostart === undefined,
      }
    },
    [autostart, autostartError, writeAutostart],
  )

  // load and save are built once and never rebuilt, because the draft hook loads when its
  // loader changes: rebuilding them whenever the login item answers would re-fetch the
  // whole form and throw away the edits in progress.
  const io = useMemo(
    () => ({
      load: async (signal: AbortSignal): Promise<EntityLoad> => {
        // Autostart is unavailable on some platforms. That is a fact about this machine,
        // not a failure that should keep the rest of the form from loading, so its
        // rejection lands on its own control and the schema load is not waited on it.
        api
          .autostart()
          .then((view) => {
            if (!signal.aborted) showAutostart(view)
          })
          .catch((cause: unknown) => {
            if (!signal.aborted) setAutostartError(messageOf(cause))
          })

        const [served, settings] = await Promise.all([api.settingsSchemaLive(), api.settings()])
        return {
          fields: served.fields,
          groups: served.groups,
          modules: served.modules,
          view: settings as unknown as SettingsView,
        }
      },
      save: async (patch: Record<string, unknown>): Promise<EntitySaved> => {
        const updated = await api.updateSettings(patch)
        return {
          view: updated as unknown as SettingsView,
          nodeRestart: updated.nodeRestart,
          uiRelisten: updated.uiRelisten,
          appRestart: updated.appRestart,
          adminRestart: updated.adminRestart,
          adminRelaunch: updated.adminRelaunch,
          deferred: updated.deferred ?? [],
        }
      },
    }),
    // showAutostart never changes, so this list keeps the invariant above rather than
    // qualifying it: the loader is built once.
    [showAutostart],
  )

  const source = useMemo<EntitySource>(() => ({ ...io, external }), [io, external])
  const draft = useEntityDraft(source)

  const { setError, clearNodeRestart } = draft
  const restartNode = useCallback(async () => {
    setRestarting(true)
    setError(undefined)
    try {
      await api.restart()
      // The node was rebuilt with the saved settings; nothing stored changed, so the
      // form's values are already current. Just retire the pending-restart notice.
      clearNodeRestart()
    } catch (cause) {
      setError(messageOf(cause))
    } finally {
      setRestarting(false)
    }
  }, [setError, clearNodeRestart])

  return { ...draft, restarting, restartNode }
}
