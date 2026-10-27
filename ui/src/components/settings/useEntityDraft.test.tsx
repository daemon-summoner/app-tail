// SPDX-License-Identifier: MIT

// The draft machinery, driven against something that is not the settings document.
//
// Every other suite exercises it through the settings form, where the source happens to
// be the settings endpoints. These tests hold it against a made-up entity instead, which
// is the only way to tell "generic" from "settings-shaped": if a second entity needed its
// own hook, one of these would fail rather than the settings suites.

import { act } from "react";
import { describe, expect, it, vi } from "vitest";

import { renderScoped } from "../../test/agent";
import type { FeatureModuleInfo, SettingFieldSchema } from "../../api";
import { CardSettings } from "./CardSettings";
import {
  useEntityDraft,
  type EntityDraft,
  type EntitySource,
} from "./useEntityDraft";

function field(
  over: Partial<SettingFieldSchema> & { key: string },
): SettingFieldSchema {
  return {
    viewKey: over.key,
    kind: "string",
    secret: false,
    readOnly: false,
    derived: false,
    restart: "none",
    write: "patch",
    label: over.key,
    group: "identity",
    tier: "basic",
    module: "core",
    help: "",
    available: true,
    availableReason: "",
    ...over,
  };
}

const GADGET_FIELDS: SettingFieldSchema[] = [
  field({ key: "name", label: "Name" }),
  field({ key: "enabled", label: "Enabled", kind: "bool" }),
];

/** A source over an entity the settings registry knows nothing about. */
function gadgetSource(
  values: Record<string, unknown>,
  save: EntitySource["save"],
): EntitySource {
  return {
    load: () =>
      Promise.resolve({
        fields: GADGET_FIELDS,
        groups: [{ id: "identity", label: "Gadget", description: "" }],
        modules: [],
        view: values,
      }),
    save,
  };
}

// The module ids are the installation's, because a module switch is the installation's
// answer wherever the field it governs lives. The switch and the field it gates are this
// entity's own, which is the arrangement under test.
const GADGET_MODULES: FeatureModuleInfo[] = [
  {
    id: "telemetry",
    label: "Gadget logging",
    description: "",
    switchKey: "enabled",
  },
];

const GATED_FIELDS: SettingFieldSchema[] = [
  field({ key: "enabled", label: "Enabled", kind: "bool" }),
  field({ key: "depth", label: "Depth", kind: "int", module: "telemetry" }),
];

/** A source whose schema carries an availability answer, resolved the way an agent
 *  resolves it: once, against the values in force when the schema was asked for. */
function gatedSource(
  values: Record<string, unknown>,
  save: EntitySource["save"],
): EntitySource {
  const on = values["enabled"] === true;
  return {
    load: () =>
      Promise.resolve({
        fields: GATED_FIELDS.map((f) =>
          f.module === "core" ? f : { ...f, available: on },
        ),
        groups: [{ id: "identity", label: "Gadget", description: "" }],
        modules: GADGET_MODULES,
        view: values,
      }),
    save,
  };
}

/** Renders a probe that hands the live draft back, so a test can drive it directly. */
function drive(source: EntitySource): { current: () => EntityDraft } {
  let latest: EntityDraft | undefined;
  function Probe() {
    latest = useEntityDraft(source);
    return <CardSettings form={latest} groups={["identity"]} />;
  }
  renderScoped(<Probe />);
  return {
    current: () => {
      if (latest === undefined) throw new Error("the draft never rendered");
      return latest;
    },
  };
}

async function settle(): Promise<void> {
  await act(async () => {});
}

describe("a form over something that is not the settings document", () => {
  it("renders the entity’s own schema and values", async () => {
    const view = drive(
      gadgetSource({ name: "widget", enabled: true }, () =>
        Promise.resolve({ view: {} }),
      ),
    );
    await settle();

    expect(view.current().loaded).toBe(true);
    expect(view.current().available.map((f) => f.key)).toEqual([
      "name",
      "enabled",
    ]);
    expect(view.current().bind(GADGET_FIELDS[0]!).value).toBe("widget");
    expect(view.current().bind(GADGET_FIELDS[1]!).value).toBe(true);
  });

  // The Save on a card writes only what changed in that card's groups. A form that sent
  // the whole draft would ship every untouched value back on every save, which turns a
  // concurrent edit elsewhere into a silent overwrite.
  it("writes only the fields that were edited", async () => {
    const save = vi.fn(() =>
      Promise.resolve({ view: { name: "gizmo", enabled: true } }),
    );
    const view = drive(gadgetSource({ name: "widget", enabled: true }, save));
    await settle();

    act(() => {
      view.current().bind(GADGET_FIELDS[0]!).onChange("gizmo");
    });
    expect(view.current().dirtyGroups.has("identity")).toBe(true);

    await act(async () => {
      await view.current().saveGroup(["identity"]);
    });

    expect(save).toHaveBeenCalledWith({ name: "gizmo" });
    expect(view.current().dirtyGroups.size).toBe(0);
  });

  // Nothing was stored, so the control has to go back where it was. One left in its new
  // position claims a change the agent refused, and the next save would not resend it.
  it("puts an immediately-applied control back when the write is refused", async () => {
    const save = vi.fn(() => Promise.reject(new Error("the agent said no")));
    const view = drive(gadgetSource({ name: "widget", enabled: true }, save));
    await settle();

    act(() => {
      view.current().bindImmediate(GADGET_FIELDS[1]!).onChange(false);
    });
    await settle();

    expect(save).toHaveBeenCalledWith({ enabled: false });
    expect(view.current().bind(GADGET_FIELDS[1]!).value).toBe(true);
    expect(view.current().error).toBe("the agent said no");
  });

  // A refused group save is the opposite case: the user is mid-correction, and throwing
  // away what they typed makes them type it again to find out what was wrong with it.
  it("keeps a rejected edit in the form so it can be fixed", async () => {
    const save = vi.fn(() => Promise.reject(new Error("that name is taken")));
    const view = drive(gadgetSource({ name: "widget", enabled: true }, save));
    await settle();

    act(() => {
      view.current().bind(GADGET_FIELDS[0]!).onChange("gizmo");
    });
    await act(async () => {
      await view.current().saveGroup(["identity"]);
    });

    expect(view.current().bind(GADGET_FIELDS[0]!).value).toBe("gizmo");
    expect(view.current().error).toBe("that name is taken");
  });

  // A switch writes on the click, and the answer describes the whole entity. Folding all of
  // it back in would throw away a name half-typed beside the switch; only what the write
  // carried may take the agent's word over the reader's.
  it("keeps an unsaved edit elsewhere when an immediate control writes", async () => {
    const save = vi.fn(() =>
      Promise.resolve({ view: { name: "widget", enabled: false } }),
    );
    const view = drive(gadgetSource({ name: "widget", enabled: true }, save));
    await settle();

    act(() => {
      view.current().bind(GADGET_FIELDS[0]!).onChange("gizmo");
    });
    act(() => {
      view.current().bindImmediate(GADGET_FIELDS[1]!).onChange(false);
    });
    await settle();

    expect(save).toHaveBeenCalledWith({ enabled: false });
    expect(view.current().bind(GADGET_FIELDS[1]!).value).toBe(false);
    expect(view.current().bind(GADGET_FIELDS[0]!).value).toBe("gizmo");
    expect(view.current().dirtyGroups.has("identity")).toBe(true);

    await act(async () => {
      await view.current().saveGroup(["identity"]);
    });
    expect(save).toHaveBeenLastCalledWith({ name: "gizmo" });
  });

  // Two switches a moment apart are two writes in flight. A refusal of the second puts
  // back only what the second carried: the first was stored, and its answer stands.
  it("puts back only what a refused write carried, keeping a write stored meanwhile", async () => {
    let answerFirst: (() => void) | undefined;
    let refuseSecond: (() => void) | undefined;
    const save = vi.fn((patch: Record<string, unknown>) => {
      if ("enabled" in patch) {
        return new Promise<{ view: Record<string, unknown> }>((resolve) => {
          answerFirst = () => resolve({ view: { name: "widget", enabled: false } });
        });
      }
      return new Promise<{ view: Record<string, unknown> }>((_resolve, reject) => {
        refuseSecond = () => reject(new Error("that name is taken"));
      });
    });
    const view = drive(gadgetSource({ name: "widget", enabled: true }, save));
    await settle();

    act(() => {
      view.current().bindImmediate(GADGET_FIELDS[1]!).onChange(false);
    });
    act(() => {
      view.current().bindImmediate(GADGET_FIELDS[0]!).onChange("gizmo");
    });
    act(() => {
      answerFirst?.();
    });
    await settle();
    expect(view.current().saving).toBe(true);
    act(() => {
      refuseSecond?.();
    });
    await settle();

    expect(view.current().bind(GADGET_FIELDS[1]!).value).toBe(false);
    expect(view.current().bind(GADGET_FIELDS[0]!).value).toBe("widget");
    expect(view.current().dirtyGroups.size).toBe(0);
    expect(view.current().saving).toBe(false);
  });

  // A control that writes on the click is held still while a write is out, so the race
  // above is one a reader has to try for rather than one a quick hand falls into.
  it("holds the immediate controls still while a write is out", async () => {
    let answer: (() => void) | undefined;
    const save = vi.fn(
      () =>
        new Promise<{ view: Record<string, unknown> }>((resolve) => {
          answer = () => resolve({ view: { name: "widget", enabled: false } });
        }),
    );
    const view = drive(gadgetSource({ name: "widget", enabled: true }, save));
    await settle();
    expect(view.current().bindImmediate(GADGET_FIELDS[1]!).disabled).toBe(false);

    act(() => {
      view.current().bindImmediate(GADGET_FIELDS[1]!).onChange(false);
    });
    expect(view.current().bindImmediate(GADGET_FIELDS[0]!).disabled).toBe(true);
    // A draft-only control is not in the race: it writes on Save, not on the click.
    expect(view.current().bind(GADGET_FIELDS[0]!).disabled).toBe(false);

    act(() => {
      answer?.();
    });
    await settle();
    expect(view.current().bindImmediate(GADGET_FIELDS[0]!).disabled).toBe(false);
  });

  // The other direction: the agent's answer for what was written wins over the draft, so a
  // value the agent normalised on the way in is what the control shows afterwards.
  it("shows what the agent stored for the field it was sent", async () => {
    const save = vi.fn(() =>
      Promise.resolve({ view: { name: "gizmo-2", enabled: true } }),
    );
    const view = drive(gadgetSource({ name: "widget", enabled: true }, save));
    await settle();

    act(() => {
      view.current().bind(GADGET_FIELDS[0]!).onChange("Gizmo 2");
    });
    await act(async () => {
      await view.current().saveGroup(["identity"]);
    });

    expect(view.current().bind(GADGET_FIELDS[0]!).value).toBe("gizmo-2");
    expect(view.current().dirtyGroups.size).toBe(0);
  });

  // An empty patch is a round trip that stores nothing and comes back reporting a save
  // that did not happen.
  it("does not call the agent when nothing changed", async () => {
    const save = vi.fn(() => Promise.resolve({ view: {} }));
    const view = drive(gadgetSource({ name: "widget", enabled: true }, save));
    await settle();

    await act(async () => {
      await view.current().saveGroup(["identity"]);
    });

    expect(save).not.toHaveBeenCalled();
  });

  // The agent resolves availability once, when the schema is asked for, and a save moves
  // what is stored without moving that answer. Measuring the switch against what is stored
  // would therefore hide a module's settings the instant its save landed, and give them
  // back only on a page reload -- the switch and the settings it governs on one card is
  // the whole shape this form is drawn in.
  it("keeps a module’s settings reachable once its switch is saved on", async () => {
    const save = vi.fn(() => Promise.resolve({ view: { enabled: true, depth: 3 } }));
    const view = drive(gatedSource({ enabled: false, depth: 3 }, save));
    await settle();

    expect(view.current().available.map((f) => f.key)).toEqual(["enabled"]);

    act(() => {
      view.current().bindImmediate(GATED_FIELDS[0]!).onChange(true);
    });
    await settle();

    expect(save).toHaveBeenCalledWith({ enabled: true });
    expect(view.current().available.map((f) => f.key)).toEqual([
      "enabled",
      "depth",
    ]);
  });

  it("reports a failed load rather than rendering an empty form as if it were loaded", async () => {
    const view = drive({
      load: () => Promise.reject(new Error("the agent is not answering")),
      save: () => Promise.resolve({ view: {} }),
    });
    await settle();

    expect(view.current().loaded).toBe(false);
    expect(view.current().error).toBe("the agent is not answering");
  });
});
