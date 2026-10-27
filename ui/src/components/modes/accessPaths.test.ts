// SPDX-License-Identifier: MIT

import { describe, expect, it } from 'vitest'

import { accessPaths, type AccessPath, type AccessPathViews } from './accessPaths'
import { settingsSchema, type AutoMapView, type Forward, type ProxyView } from '../../api'
import { makeAutoMap, makeFabric, makeForward, makeInterface, makeProxy } from '../../test/agent'

/** pathsOver decides the paths for one arrangement of the machine, defaulting every
 *  view the case does not care about to the state a fresh install is in. A case that
 *  names `tun` as undefined means the view has not arrived, and gets exactly that. */
function pathsOver(
  over: Partial<AccessPathViews> & { proxyEnabled?: boolean; interfaceEnabled?: boolean },
): AccessPath[] {
  return accessPaths(
    { proxyEnabled: over.proxyEnabled ?? false, interfaceEnabled: over.interfaceEnabled ?? false },
    {
      forwards: over.forwards ?? [],
      automap: over.automap,
      proxy: over.proxy,
      tun: 'tun' in over ? over.tun : makeInterface(),
      fabric: over.fabric ?? makeFabric(),
    },
    settingsSchema,
  )
}

/** pathNamed is the one path a case is about, by the label the tiles show. */
function pathNamed(paths: readonly AccessPath[], label: string): AccessPath {
  const path = paths.find((p) => p.label === label)
  if (path === undefined) throw new Error(`no path is called ${label}`)
  return path
}

describe('how this machine reaches its networks', () => {
  // The mode that puts every connection on one interface reports through its own view, not
  // the tailnet's. Read from the tailnet's alone, a machine carrying every network reads as
  // "not selected" -- the arrangement showing as no arrangement at all.
  it('reports the one-interface mode as carrying, on the interface it is carrying on', () => {
    const paths = pathsOver({
      tun: makeInterface({ enabled: true, configured: 'fabric' }),
      fabric: makeFabric({ running: true, interface: 'utun7' }),
    })

    expect(pathNamed(paths, 'Network interface').status).toEqual({ tone: 'running', label: 'on utun7' })
  })

  // Set and carrying nothing is the state with no symptom: every address on every
  // connection is unreachable while the mode itself looks chosen and fine.
  it('does not report a mode that is set and carrying nothing as running', () => {
    const paths = pathsOver({
      tun: makeInterface({ enabled: true, configured: 'fabric' }),
      fabric: makeFabric({ error: 'the privileged helper is not installed' }),
    })

    expect(pathNamed(paths, 'Network interface').status).toEqual({ tone: 'error', label: 'not carrying' })
  })

  // Chosen, nothing wrong, and nothing carried: the connections have not been restarted onto
  // the interface yet. It is not an error and it is not working, and the status has to be
  // the third thing rather than round to either.
  it('reports a one-interface mode nothing has moved onto yet as waiting', () => {
    const paths = pathsOver({ tun: makeInterface({ enabled: true, configured: 'fabric' }) })

    expect(pathNamed(paths, 'Network interface').status).toEqual({
      tone: 'pending',
      label: 'waiting for a restart',
    })
  })

  // The tailnet's own interface mode has the same waiting state, and a machine with the
  // module on and no mode chosen at all is off rather than broken.
  it.each([
    ['the tailnet interface, not yet in force', 'tun', 'pending', 'waiting for a restart'],
    ['no mode chosen at all', '', 'off', 'not selected'],
  ])('reports %s', (_case, configured, tone, label) => {
    const paths = pathsOver({ tun: makeInterface({ enabled: true, configured }) })

    expect(pathNamed(paths, 'Network interface').status).toEqual({ tone, label })
  })

  it('reports the tailnet on its own interface', () => {
    const paths = pathsOver({
      tun: makeInterface({ enabled: true, configured: 'tun', inForce: true, interface: 'utun9' }),
    })

    expect(pathNamed(paths, 'Network interface').status).toEqual({ tone: 'running', label: 'on utun9' })
  })

  // A node that asked for an interface and could not create one keeps running without it.
  // That is the failure with a symptom nobody can trace: every program still reaches
  // nothing, while the module reads as on.
  it('reports a node that fell back off its interface as an error', () => {
    const paths = pathsOver({
      tun: makeInterface({
        enabled: true,
        configured: 'tun',
        fallback: 'the privileged helper is not installed',
      }),
    })

    expect(pathNamed(paths, 'Network interface').status).toEqual({ tone: 'error', label: 'fell back' })
  })

  // The view arrives on its own request, after the settings as often as not, and a failed
  // request never arrives. Neither is the module being off.
  it('reports no interface view at all as still reading', () => {
    const paths = pathsOver({ tun: undefined })

    expect(pathNamed(paths, 'Network interface').status).toEqual({ tone: 'pending', label: 'reading' })
  })
})

// A forward that is switched on and is not listening is the one state worth a colour here:
// the port it promised is not open, and the program pointed at it fails with a connection
// refused that says nothing about app-tail. Configured-and-off is a choice, not a fault.
describe('what the forwards are doing', () => {
  it.each<[string, Forward[], string, string]>([
    ['nothing configured', [], 'off', 'none yet'],
    [
      'every forward switched off',
      [makeForward({ enabled: false, state: 'stopped' })],
      'off',
      '1 configured, all off',
    ],
    [
      'one of two not listening',
      [makeForward(), makeForward({ id: 'fwd-web', name: 'web', state: 'error' })],
      'error',
      '1 of 2 running',
    ],
    ['both listening', [makeForward(), makeForward({ id: 'fwd-web', name: 'web' })], 'running', '2 running'],
  ])('reports %s', (_case, forwards, tone, label) => {
    expect(pathNamed(pathsOver({ forwards }), 'Port forwards').status).toEqual({ tone, label })
  })

  // The ports opened for peers automatically are forwards too, and a count that left them
  // out would disagree with the forwards page for anyone using the feature.
  it('counts the ports opened automatically alongside the ones that were asked for', () => {
    const automap: AutoMapView = makeAutoMap({ enabled: true, mapped: 4 })
    const paths = pathsOver({ forwards: [makeForward()], automap })

    expect(pathNamed(paths, 'Port forwards').status.label).toBe('1 running, 4 automatic')
  })

  // The forwards are not a module: there is nothing to switch, so the path offers no switch
  // rather than one that does nothing.
  it('offers no switch for the forwards', () => {
    expect(pathNamed(pathsOver({}), 'Port forwards').control).toEqual({ kind: 'always' })
  })
})

// The status repeats the agent's own answer about the proxy rather than deciding from the
// switch: a proxy that is on and could not bind its port is the failure a reader needs,
// and the switch alone reports that as working.
describe('what the proxies are doing', () => {
  it.each<[string, ProxyView, string, string]>([
    ['switched off', makeProxy(), 'off', 'off'],
    [
      'on and not bound',
      makeProxy({
        enabled: true,
        capability: { available: false, degraded: false, reason: 'the port is already in use' },
      }),
      'error',
      'not listening',
    ],
    [
      'bound but not fully working',
      makeProxy({
        enabled: true,
        listening: '127.0.0.1:1080',
        capability: { available: true, degraded: true, reason: 'the connection is not up' },
      }),
      'pending',
      'degraded',
    ],
    [
      'listening',
      makeProxy({
        enabled: true,
        listening: '127.0.0.1:1080',
        capability: { available: true, degraded: false, reason: '' },
      }),
      'running',
      '127.0.0.1:1080',
    ],
  ])('reports a proxy %s', (_case, proxy, tone, label) => {
    expect(pathNamed(pathsOver({ proxy }), 'Proxies').status).toEqual({ tone, label })
  })
})

describe('the switches beside the paths', () => {
  // The switch shows the stored value, which is what a click changes. What is in force is
  // the status beside it, and the two differ for the whole time a restart is owed.
  it('shows each switch as the form holds it, not as the agent reports it', () => {
    const paths = pathsOver({
      proxyEnabled: true,
      interfaceEnabled: false,
      proxy: makeProxy(),
      tun: makeInterface({ enabled: true, inForce: true, interface: 'utun9' }),
    })

    expect(pathNamed(paths, 'Proxies').control).toMatchObject({ kind: 'switch', on: true })
    expect(pathNamed(paths, 'Network interface').control).toMatchObject({ kind: 'switch', on: false })
  })

  it('switches the proxy with its module switch alone, owing no restart', () => {
    expect(pathNamed(pathsOver({}), 'Proxies').control).toEqual({
      kind: 'switch',
      on: false,
      patchOn: { 'proxy.enabled': true },
      patchOff: { 'proxy.enabled': false },
      restart: undefined,
    })
  })

  // The module switch on its own puts the node on no interface: the mode is what does
  // that, and a fresh machine has it at "inside app-tail only".
  it('switches the interface on with the tailnet interface mode, owing a node restart', () => {
    const control = pathNamed(pathsOver({}), 'Network interface').control

    expect(control).toEqual({
      kind: 'switch',
      on: false,
      patchOn: { 'interface.enabled': true, 'interface.mode': 'tun' },
      patchOff: { 'interface.enabled': false },
      restart: 'node',
    })
  })

  // A machine arranged for one interface over every connection keeps that arrangement
  // when its switch is turned back on: the switch is not where the mode is chosen.
  it('keeps the one-interface arrangement when switching it back on', () => {
    const control = pathNamed(
      pathsOver({ tun: makeInterface({ enabled: false, configured: 'fabric' }) }),
      'Network interface',
    ).control

    expect(control).toMatchObject({ patchOn: { 'interface.enabled': true, 'interface.mode': 'fabric' } })
  })

  // The mode the switch writes is read from the view, and until the view has arrived there
  // is nothing to read it from: a switch offered then would write `tun` over a machine
  // arranged for one interface, and owe a node restart for it.
  it('offers no switch for the interface until its view has arrived', () => {
    const control = pathNamed(pathsOver({ tun: undefined }), 'Network interface').control

    expect(control).toEqual({ kind: 'reading' })
  })

  // Off writes the module switch alone, so the mode is there again the next time.
  it('leaves the mode stored when switching the interface off', () => {
    const control = pathNamed(
      pathsOver({ interfaceEnabled: true, tun: makeInterface({ enabled: true, configured: 'fabric' }) }),
      'Network interface',
    ).control

    expect(control).toMatchObject({ patchOff: { 'interface.enabled': false } })
    expect(control).not.toMatchObject({ patchOff: { 'interface.mode': expect.anything() } })
  })

  // The restart owed is read from the schema, so the schema changing its mind changes the
  // hint with it. A schema without the field says nothing rather than guessing.
  it('says nothing about a restart when the schema does not carry the interface mode', () => {
    const paths = accessPaths(
      { proxyEnabled: false, interfaceEnabled: false },
      { forwards: [], automap: undefined, proxy: undefined, tun: makeInterface(), fabric: makeFabric() },
      [],
    )

    expect(pathNamed(paths, 'Network interface').control).toMatchObject({ restart: undefined })
  })

  it('names every path in the order the tiles show them', () => {
    expect(pathsOver({}).map((p) => p.id)).toEqual(['forwards', 'proxy', 'interface'])
  })
})
