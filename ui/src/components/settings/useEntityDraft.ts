// SPDX-License-Identifier: MIT

// The draft state behind any schema-driven form: load a schema and the values it
// describes, hold the edits, and write back the difference.
//
// Nothing here knows what it is editing. The global settings document is one such thing;
// a single connection is another. What varies is only where the schema and the values
// come from and where a patch is sent, which is what EntitySource carries.

import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import {
  ApiError,
  type DeferredSetting,
  type FeatureModuleInfo,
  type SettingFieldSchema,
  type SettingGroupInfo,
} from '../../api'
import {
  availableFields,
  draftFrom,
  exampleFor,
  fieldReason,
  isPatchable,
  patchFrom,
  patchOne,
  secretIsStored,
  type Draft,
  type DraftValue,
  type SettingsView,
} from './fieldState'

/** Everything one control needs, resolved from whichever place holds that field's
 *  value. A field is bound by its write path, not by its name. */
export interface FieldBinding {
  value: DraftValue
  example: string
  onChange: (next: DraftValue) => void
  stored: boolean
  error: string | undefined
  disabled: boolean
}

/** What a write came to: stored, or refused with the agent's reason. */
type WriteOutcome = { stored: true } | { stored: false; reason: string }

/** What a schema and its values look like once they have arrived. */
export interface EntityLoad {
  fields: readonly SettingFieldSchema[]
  groups: readonly SettingGroupInfo[]
  modules: readonly FeatureModuleInfo[]
  view: SettingsView
}

/** What the agent reports having stored. The four optional members are how a global
 *  save says the write needs something more before it is in force; an entity whose
 *  writes always apply at once simply leaves them out. */
export interface EntitySaved {
  view: SettingsView
  nodeRestart?: boolean
  uiRelisten?: boolean
  appRestart?: boolean
  adminRestart?: boolean
  adminRelaunch?: boolean
  deferred?: readonly DeferredSetting[]
}

/** Where a form's schema, values and writes live. */
export interface EntitySource {
  load: (signal: AbortSignal) => Promise<EntityLoad>
  save: (patch: Record<string, unknown>) => Promise<EntitySaved>
  /** external binds a field written through its own endpoint rather than through the
   *  patch, returning undefined for every field that is not one. It exists because such
   *  a field has no draft behind it: its live value comes from somewhere this hook
   *  cannot see, so it cannot be diffed, saved or rolled back with the rest. */
  external?: (field: SettingFieldSchema) => FieldBinding | undefined
}

/** The subset of a form a control needs to render itself. Every schema-driven component
 *  takes this rather than a particular form, so a card written against the settings
 *  document renders a connection with no change. */
export interface EntityForm {
  /** available are the fields this configuration can write right now, schema order. */
  available: readonly SettingFieldSchema[]
  saving: boolean
  /** saveGroup writes only the settings in the named groups. Each card owns its own
   *  groups and has a Save of its own, so a patch carrying the whole draft would let one
   *  card ship an edit a user made on another and never submitted. */
  saveGroup: (groups: readonly string[]) => Promise<void>
  /** dirtyGroups are the groups holding an edit that has not been written. A card reads
   *  it to know whether its Save has anything to do. */
  dirtyGroups: ReadonlySet<string>
  bind: (field: SettingFieldSchema) => FieldBinding
  /** bindImmediate binds a control that has no Save button behind it: the change is
   *  written as soon as it is made. A form holds a draft because it has a Save; a switch
   *  in a control panel has nowhere to hold one. */
  bindImmediate: (field: SettingFieldSchema) => FieldBinding
}

export interface EntityDraft extends EntityForm {
  /** loaded is false until both the schema and the values have arrived; the form renders
   *  nothing editable before then, because it would be guessing. */
  loaded: boolean
  groups: readonly SettingGroupInfo[]
  error: string | undefined
  /** applyPatch writes exactly the settings it is given, for a control that changes more
   *  than one at once. It resolves to what the write came to rather than rejecting: the
   *  form's own notice carries a refusal either way, and a control with a dialog or a
   *  notice of its own reads the outcome, because the form's notice is at the top of the
   *  page and the control is wherever the person is looking. */
  applyPatch: (patch: Record<string, unknown>) => Promise<WriteOutcome>
  nodeRestartPending: boolean
  uiRelistenPending: boolean
  /** A setting the process read when it started and does not read again. The value is
   *  stored and correct; the only thing outstanding is a start that has not happened. */
  appRestartPending: boolean
  /** A change needing administrator rights this process does not hold. The value is
   *  stored; what is missing is a start that can ask for them. */
  adminRestartPending: boolean
  /** The agent is restarting itself to obtain those rights, which on Windows is what puts
   *  the prompt on screen. The page goes away with the process and comes back with it. */
  adminRelaunchPending: boolean
  /** What the last save stored without it taking effect. It describes that save only:
   *  the durable view of which of these settings are in force is the dashboard card,
   *  which polls, so keeping stale entries here would outlive the wait they describe. */
  deferred: readonly DeferredSetting[]
  /** clearNodeRestart retires the pending-restart notice once the restart has happened.
   *  Performing the restart is the caller's business; this hook only tracked the need. */
  clearNodeRestart: () => void
  setError: (message: string | undefined) => void
}

export function messageOf(cause: unknown): string {
  return cause instanceof Error ? cause.message : String(cause)
}

/** No switches held elsewhere, which is the case for a form whose module switches are its
 *  own fields. A module-level constant so a form that passes nothing does not rebuild its
 *  gate on every render. */
const NO_GATES: Draft = {}

/**
 * useEntityDraft is the form behind one entity.
 *
 * `gates` are the module switches this entity's fields are gated on when the switches
 * belong to something else -- a connection's fields are gated on the installation's
 * switches, which are not the connection's own settings. Passing the live values in is
 * what lets flipping one of those switches reveal or hide the settings it governs at once,
 * the same way a form whose switches are its own fields already behaves.
 */
export function useEntityDraft(source: EntitySource, gates: Draft = NO_GATES): EntityDraft {
  const [schema, setSchema] = useState<readonly SettingFieldSchema[]>([])
  const [groups, setGroups] = useState<readonly SettingGroupInfo[]>([])
  const [modules, setModules] = useState<readonly FeatureModuleInfo[]>([])
  const [view, setView] = useState<SettingsView | undefined>(undefined)
  const [draft, setDraft] = useState<Draft>({})
  const [stored, setStored] = useState<Draft>({})
  const [error, setError] = useState<string | undefined>(undefined)
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({})
  // Writes in flight, counted: two switches flipped a moment apart are two writes, and the
  // form is saving until the last of them has answered.
  const [inFlight, setInFlight] = useState(0)
  // `stored` as of the latest answer, readable from inside a write that started before
  // that answer came: what a refusal puts back is where the agent stands now, not where
  // it stood when the refused write began.
  const latestStored = useRef<Draft>({})
  // Node-identity changes can be applied in place; a dashboard-address change and a
  // setting the process reads only at start can take effect only when the whole process
  // restarts. They accumulate across saves and clear only when the corresponding restart
  // actually happens.
  const [nodeRestartPending, setNodeRestartPending] = useState(false)
  const [uiRelistenPending, setUiRelistenPending] = useState(false)
  const [appRestartPending, setAppRestartPending] = useState(false)
  const [adminRestartPending, setAdminRestartPending] = useState(false)
  const [adminRelaunchPending, setAdminRelaunchPending] = useState(false)
  const [deferred, setDeferred] = useState<readonly DeferredSetting[]>([])
  // Where the switches stood when the agent answered, which is the configuration the
  // `available` it served describes. A save moves `stored` and leaves the schema where it
  // was, so this is the only record of what those flags were an answer about: without it,
  // turning a module on would hide the settings it governs until the page was reloaded.
  const [gatesAtLoad, setGatesAtLoad] = useState<Draft>(NO_GATES)
  const [valuesAtLoad, setValuesAtLoad] = useState<Draft>({})

  const { load, save, external } = source

  // Read inside the load, which must not re-run when a switch moves: reloading would throw
  // away whatever the user has typed since. Kept current here rather than in the load's own
  // dependencies, which is what would cause that reload.
  const latestGates = useRef(gates)
  useEffect(() => {
    latestGates.current = gates
  }, [gates])

  useEffect(() => {
    const ctrl = new AbortController()

    load(ctrl.signal)
      .then((loaded) => {
        if (ctrl.signal.aborted) return
        const values = draftFrom(loaded.fields, loaded.view)
        setSchema(loaded.fields)
        setGroups(loaded.groups)
        setModules(loaded.modules)
        setView(loaded.view)
        setDraft(values)
        setStored(values)
        latestStored.current = values
        setValuesAtLoad(values)
        setGatesAtLoad(latestGates.current)
      })
      .catch((cause: unknown) => {
        if (!ctrl.signal.aborted) setError(messageOf(cause))
      })

    return () => ctrl.abort()
  }, [load])

  const loaded = view !== undefined

  // The switches held elsewhere stand beside this form's own values, in both positions
  // availableFields reads: what they are now decides what is reachable, and what they were
  // when the schema arrived is what the agent's answer was about.
  const gatedDraft = useMemo(() => ({ ...draft, ...gates }), [draft, gates])
  const gatedAtLoad = useMemo(
    () => ({ ...valuesAtLoad, ...gatesAtLoad }),
    [valuesAtLoad, gatesAtLoad],
  )

  const available = useMemo(
    () => availableFields(schema, modules, gatedDraft, gatedAtLoad),
    [schema, modules, gatedDraft, gatedAtLoad],
  )

  const setValue = useCallback((key: string, next: DraftValue) => {
    setDraft((prev) => ({ ...prev, [key]: next }))
    // The user is answering the complaint; leaving it under the control they are
    // editing would make a stale message look like a live rejection.
    setFieldErrors((prev) => {
      if (prev[key] === undefined) return prev
      const rest = { ...prev }
      delete rest[key]
      return rest
    })
  }, [])

  /** The pending write, keyed by the group each setting is drawn under. Built from the
   *  same diff a whole-form save uses, so a card's Save and the draft never disagree
   *  about what actually changed. */
  const pendingByGroup = useMemo(() => {
    const patch = patchFrom(schema, modules, gatedDraft, stored, gatedAtLoad) as Record<
      string,
      unknown
    >
    const byGroup = new Map<string, Record<string, unknown>>()
    for (const field of schema) {
      if (!(field.key in patch)) continue
      const group = byGroup.get(field.group) ?? {}
      group[field.key] = patch[field.key]
      byGroup.set(field.group, group)
    }
    return byGroup
  }, [schema, modules, gatedDraft, stored, gatedAtLoad])

  const dirtyGroups = useMemo(() => new Set(pendingByGroup.keys()), [pendingByGroup])

  /** store writes a patch and folds the result back in, reporting whether it was stored.
   *  rollback is what a refusal does to the draft: a whole-group save keeps what the user
   *  typed so they can fix it, and a switch that applied on the click goes back where it
   *  was rather than claiming a change the agent refused. Only the keys the refused write
   *  carried go back: another write may have been stored in the meantime, and its answer
   *  stands. */
  const store = useCallback(
    async (patch: Record<string, unknown>, rollback: boolean): Promise<WriteOutcome> => {
      setInFlight((n) => n + 1)
      setError(undefined)
      setFieldErrors({})
      try {
        const updated = await save(patch)
        const values = draftFrom(schema, updated.view)
        const before = latestStored.current
        setView(updated.view)
        // What this write carried takes the agent's answer. An edit still unsaved in
        // another control survives: a switch flipped beside a half-typed name is not a
        // request to throw the name away.
        setDraft((prev) => {
          const next = { ...values }
          for (const [key, typed] of Object.entries(prev)) {
            if (key in patch || typed === before[key]) continue
            next[key] = typed
          }
          return next
        })
        setStored(values)
        latestStored.current = values
        setNodeRestartPending((prev) => prev || updated.nodeRestart === true)
        setUiRelistenPending((prev) => prev || updated.uiRelisten === true)
        setAppRestartPending((prev) => prev || updated.appRestart === true)
        setAdminRestartPending((prev) => prev || updated.adminRestart === true)
        setAdminRelaunchPending((prev) => prev || updated.adminRelaunch === true)
        setDeferred(updated.deferred ?? [])
        return { stored: true }
      } catch (cause) {
        if (rollback) {
          const current = latestStored.current
          setDraft((prev) => {
            const next = { ...prev }
            for (const key of Object.keys(patch)) {
              if (key in current) next[key] = current[key] as DraftValue
              else delete next[key]
            }
            return next
          })
        }
        const reason = messageOf(cause)
        setError(reason)
        if (cause instanceof ApiError && cause.field !== undefined) {
          const key = cause.field
          if (schema.some((f) => f.key === key)) {
            setFieldErrors({ [key]: fieldReason(cause.message, key) })
          }
        }
        return { stored: false, reason }
      } finally {
        setInFlight((n) => n - 1)
      }
    },
    [save, schema],
  )
  const saving = inFlight > 0

  const saveGroup = useCallback(
    async (names: readonly string[]) => {
      if (!loaded) return
      const patch: Record<string, unknown> = {}
      for (const group of names) Object.assign(patch, pendingByGroup.get(group) ?? {})
      if (Object.keys(patch).length === 0) return
      await store(patch, false)
    },
    [loaded, pendingByGroup, store],
  )

  const applyPatch = useCallback(
    async (patch: Record<string, unknown>): Promise<WriteOutcome> => {
      if (!loaded) return { stored: false, reason: 'The settings have not loaded yet.' }
      // An empty patch would be a round trip that stores nothing and comes back
      // reporting a save that did not happen. Nothing was refused either.
      if (Object.keys(patch).length === 0) return { stored: true }
      return store(patch, true)
    },
    [loaded, store],
  )

  const applyOne = useCallback(
    async (field: SettingFieldSchema, next: DraftValue) => {
      // The control moves under the cursor before the agent has answered, because a
      // switch that stays put for a round trip reads as a click that missed. A refusal
      // puts it back.
      setDraft((prev) => ({ ...prev, [field.key]: next }))
      await applyPatch(patchOne(field, next))
    },
    [applyPatch],
  )

  const bind = useCallback(
    (field: SettingFieldSchema): FieldBinding => {
      const own = external?.(field)
      if (own !== undefined) return own
      return {
        value: draft[field.key] ?? '',
        example: view === undefined ? '' : exampleFor(field, view),
        onChange: (next) => setValue(field.key, next),
        stored: field.secret && view !== undefined && secretIsStored(field, view),
        error: fieldErrors[field.key],
        disabled: !isPatchable(field),
      }
    },
    [draft, fieldErrors, view, external, setValue],
  )

  const bindImmediate = useCallback(
    (field: SettingFieldSchema): FieldBinding => {
      // A field with its own endpoint already writes on the click and has no draft
      // behind it, so it is left exactly as bind built it.
      if (external?.(field) !== undefined) return bind(field)
      // Held still while a write is out: a second switch flipped before the first has
      // answered is a second write racing the first, and a refusal of either would put
      // back what the other stored.
      const own = bind(field)
      return {
        ...own,
        disabled: own.disabled || saving,
        onChange: (next) => void applyOne(field, next),
      }
    },
    [bind, external, applyOne, saving],
  )

  const clearNodeRestart = useCallback(() => setNodeRestartPending(false), [])

  return {
    loaded,
    groups,
    available,
    error,
    saving,
    saveGroup,
    dirtyGroups,
    bind,
    bindImmediate,
    applyPatch,
    nodeRestartPending,
    uiRelistenPending,
    appRestartPending,
    adminRestartPending,
    adminRelaunchPending,
    deferred,
    clearNodeRestart,
    setError,
  }
}
