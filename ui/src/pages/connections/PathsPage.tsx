// SPDX-License-Identifier: MIT

// How this machine is on its networks.
//
// The three cards are not a fourth switch beside the ones they write. Each is a name for
// a combination of the switches this app already had, and the mode it reports is those
// switches read back -- both halves served by the agent on the one field, so choosing a
// mode and seeing which one is chosen cannot disagree.
//
// The switches themselves stay independent and stay reachable, because they layer: a
// machine on the network interface may still want a proxy for a program that is pointed
// at one, and taking that away to make three cards mutually exclusive would remove a
// working arrangement to tidy up a picture.

import type { SettingFieldSchema, SettingOption } from '../../api'
import { FabricStatus } from '../../components/mode/FabricStatus'
import { InterfaceModeCard } from '../../components/mode/InterfaceModeCard'
import { Panel } from '../../components/Panel'
import { ModuleSwitch } from '../../components/settings/CardSettings'
import type { SettingsForm } from '../../components/settings/useSettingsDraft'
import { usePolled } from '../../data/StoreProvider'

/** The field the whole page is about: which mode this machine is in, and what each mode
 *  writes. Both come from the agent, so this page holds neither. */
const MODE_KEY = 'mode.primary'

/**
 * layeredSwitches are the module switches the cards write, read out of what the cards
 * write rather than listed here.
 *
 * Deriving them is what keeps this block honest: a mode that starts writing a fourth
 * switch puts that switch on this page by itself, and one that stops writing a switch
 * takes it off, with nothing in this file to keep in step.
 */
function layeredSwitches(
  field: SettingFieldSchema,
  available: readonly SettingFieldSchema[],
): SettingFieldSchema[] {
  const written = new Set((field.options ?? []).flatMap((o) => Object.keys(o.applies ?? {})))
  return available.filter(
    (f) =>
      f.moduleSwitch !== undefined && written.has(f.key) && !OWNED_ELSEWHERE.includes(f.key),
  )
}

/** The mode whose whole point is what it carries, so it is the one mode with a second
 *  panel below the picker. It mirrors config.RunFabric. */
const FABRIC_MODE = 'fabric'

/** The switch the interface card below already owns. Both modes that install an interface
 *  write it, so without this it would appear twice on one page -- and a switch a reader can
 *  find in two places is one they cannot tell the state of at a glance. */
const OWNED_ELSEWHERE = ['interface.enabled']

export function PathsPage({ form }: { form: SettingsForm }) {
  const field = form.available.find((f) => f.key === MODE_KEY)
  const fabric = usePolled('fabric')
  const iface = usePolled('tun')

  if (!form.loaded || field === undefined) {
    return (
      <section className="panel" aria-label="How app-tail runs here">
        <div className="panel-body">
          <p className="module-off">
            {form.error ?? 'Reading how this machine is arranged…'}
          </p>
        </div>
      </section>
    )
  }

  const current = form.bind(field).value
  const group = form.groups.find((g) => g.id === field.group)

  return (
    <div className="deck">
      <Panel title={group?.label ?? field.label} wide info={<p>{group?.description}</p>}>
        <div className="mode-cards" role="radiogroup" aria-label={field.label}>
          {(field.options ?? []).map((option) => (
            <ModeCard
              key={option.value}
              option={option}
              chosen={option.value === current}
              busy={form.saving}
              onChoose={() => void form.applyPatch(option.applies ?? {})}
            />
          ))}
        </div>
      </Panel>

      <FabricStatus
        view={fabric.data}
        chosen={current === FABRIC_MODE}
        error={fabric.error}
      />

      {/* The interface module's own state and settings: the privileged helper, what an
          unclean exit left behind, and the interface's name and pool. Both modes that
          install an interface need it, and a machine in neither still needs somewhere to
          read what an earlier run left on it. */}
      {iface.data ? <InterfaceModeCard tun={iface.data} form={form} /> : null}

      <AlsoRunning form={form} field={field} />
    </div>
  )
}

function ModeCard({
  option,
  chosen,
  busy,
  onChoose,
}: {
  option: SettingOption
  chosen: boolean
  busy: boolean
  onChoose: () => void
}) {
  return (
    // A radio rather than a button, because these are one choice with three positions and
    // that is what a reader driving this from the keyboard expects to find.
    <label className={chosen ? 'mode-card chosen' : 'mode-card'}>
      <input
        type="radio"
        name="mode"
        value={option.value}
        checked={chosen}
        disabled={busy}
        onChange={onChoose}
      />
      <span className="mode-card-name">{option.label}</span>
      <span className="mode-card-help">{option.help}</span>
    </label>
  )
}

/**
 * The switches the modes are shortcuts for, still reachable under their own names.
 *
 * They are here rather than only on their own cards because this is the page someone
 * comes to when they want something other than one of the three arrangements -- and a
 * mode picker that hides the switches it wrote is one nobody can get out of.
 */
function AlsoRunning({ form, field }: { form: SettingsForm; field: SettingFieldSchema }) {
  const switches = layeredSwitches(field, form.available)
  if (switches.length === 0) return null

  return (
    <Panel title="Also running" wide>
      <p className="hint">
        These layer. Choosing a mode above sets them together; setting one here changes
        only that, and the mode follows. Each one&rsquo;s own settings stay on its page.
      </p>
      <div className="mode-switches">
        {switches.map((f) => (
          <ModuleSwitch key={f.key} form={form} switchKey={f.key} />
        ))}
      </div>
    </Panel>
  )
}
