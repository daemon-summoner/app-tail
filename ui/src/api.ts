// SPDX-License-Identifier: MIT

// Typed client for the agent's loopback management API. Most shapes here mirror the
// Go DTOs in internal/httpapi/deps.go; Settings and SettingsPatch are generated from
// the settings field registry (see ./generated/settingsSchema).

import type {
  FeatureModuleInfo,
  SettingFieldSchema,
  SettingGroupInfo,
  Settings,
  SettingsPatch,
} from './generated/settingsSchema'
import { markSignedOut, sessionToken } from './auth'

export type { Settings, SettingsPatch } from './generated/settingsSchema'
export { settingsSchema, settingsGroups, featureModules } from './generated/settingsSchema'
export type {
  SettingFieldSchema,
  SettingGroupInfo,
  FeatureModuleInfo,
  SettingConstraint,
  SettingOption,
  SettingKind,
  SettingGroup,
  SettingTier,
  FeatureModule,
  RestartClass,
  WriteVia,
} from './generated/settingsSchema'

export type Direction = 'to_local' | 'to_tailnet'
export type Protocol = 'tcp' | 'udp' | 'both'
type ForwardState = 'running' | 'stopped' | 'error' | ''

export interface Forward {
  id: string
  name: string
  /** The connection this forward crosses. Every stored forward names one. */
  tunnelId: string
  direction: Direction
  protocol: Protocol
  bindAddr: string
  /** Consent to a bindAddr other machines can reach; the agent refuses one without it. */
  exposeToNetwork: boolean
  listenPort: number
  target: string
  enabled: boolean
  udpTimeoutSec: number
  state: ForwardState
  error?: string
  activeTcp: number
  activeUdp: number
  bytesUp: number
  bytesDown: number
  listening?: string
  endpoint: string
  /** Which module created this forward; absent means a user configured it. A derived
   *  forward is rebuilt from the tailnet on every reconcile, so the edit controls are
   *  hidden rather than offered and then refused. */
  source?: 'auto'
  /** Something true about this forward that its own state cannot show — it is listening
   *  beyond this machine, or the node is refusing the connections it would carry. Absent
   *  when there is nothing to say. */
  warning?: string
}

export interface ForwardSpec {
  name?: string
  tunnelId?: string
  direction?: Direction
  protocol?: Protocol
  bindAddr?: string
  listenPort?: number
  target?: string
  enabled?: boolean
  udpTimeoutSec?: number
  exposeToNetwork?: boolean
}

export interface Status {
  /** The connection this is about: the node this process runs. */
  tunnelId: string
  backendState: string
  running: boolean
  /**
   * A login is waiting to be completed. The URL that completes it is not here: it
   * enrolls this machine on a tailnet, so it is handed over by `loginUrl()`, a
   * state-changing request the agent's same-origin guard covers.
   */
  authPending?: boolean
  hostname?: string
  dnsName?: string
  tailscaleIps?: string[]
  loginName?: string
  tags?: string[]
  authMode: string
  problem?: string
  version?: string
  /** The stack the node is really on: 'userspace' or 'tun'. */
  network?: string
  /** Why that is not the stack the settings asked for, absent when it is. A node that
   *  fell back is running and answers every other field like one that did not, so this
   *  is the only field that says so. */
  networkFallback?: string
  /** Set when the stored configuration could not be used, so this run started on the
   *  defaults. Absent on every normal run. */
  configQuarantine?: ConfigQuarantine
  /** Set when the dashboard could not bind the configured address and is on one the
   *  system assigned. Absent on every normal run. */
  dashboardMoved?: DashboardMoved
  /** Network changes the root helper refuses until an administrator approves them. Absent
   *  when nothing is waiting. */
  approvals?: Approvals
}

/** One change to this machine's networking that is waiting for an administrator. */
export interface ApprovalNeed {
  kind: 'full-tunnel' | 'route' | 'system-dns' | 'dns-domain' | 'openvpn-remote' | 'tls-interception'
  /** A range, a domain, or host:port. Absent for the kinds that are only yes or no. */
  value?: string
  /** openvpn-remote only. */
  caSha256?: string[]
  /** What the change does, in words for a person rather than an administrator's checklist. */
  reason: string
  /** Which parts of app-tail asked for it: "interface", "fabric", "system-dns",
   *  "tls-interception", or "openvpn:<connectionId>". */
  features: string[]
}

/** Everything waiting for approval, and the terminal line that approves exactly that. The
 *  agent decides what an approval covers from what is pending, never from a request. */
export interface Approvals {
  needs: ApprovalNeed[]
  command: string
}

/** A configuration document app-tail could not use, and where it was kept. Every setting
 *  on screen while this is set is a default rather than a value someone chose. */
export interface ConfigQuarantine {
  path: string
  reason: string
  at: string
}

/** A dashboard on an address nobody chose. The stored address is rewritten to the one it
 *  landed on, so the settings screen shows this port as the chosen one and this is all
 *  that says otherwise. */
export interface DashboardMoved {
  configured: string
  bound: string
  reason: string
}

/** Whether a module is working, and if not why. Mirrors httpapi.Capability. */
interface Capability {
  available: boolean
  degraded: boolean
  reason?: string
  /** Limits hold whether or not the module is working — the exposure a user accepts
   *  by turning it on is one of these, not an error. */
  limits?: string[]
}

/** One interval's worth of movement, as the agent measured it. Rates are bytes per
 *  second so a series stays comparable across a tick the sampler missed. */
export interface TrafficPoint {
  at: string
  proxyUp: number
  proxyDown: number
  forwardUp: number
  forwardDown: number
  routeIn: number
  routeOut: number
  /** What the tunnel itself carried. The only lane that moves in interface mode, where
   *  traffic never passes the proxy, a forward or the subnet router. It overlaps those
   *  lanes rather than adding to them, so a reader takes the larger and never the sum. */
  tunnelUp: number
  tunnelDown: number
  /** Every open connection the agent is carrying. A gauge, so it is still true across a
   *  gap. */
  connections: number
  /** An interval that could not be measured -- a counter reset, or a machine resumed
   *  from sleep. Its rates are zero and a chart must break its line rather than draw a
   *  floor nobody observed. */
  gap?: boolean
}

/** One destination the proxy carried traffic to, or refused. */
export interface TrafficDestination {
  address: string
  bytesUp: number
  bytesDown: number
  opened: number
  active: number
  refused: number
  failed: number
}

/** One tailnet device and what has crossed to and from it. These are WireGuard's own
 *  counters, so they cover every byte the node moved and will not match the proxy's own
 *  figures -- the two are counting different things. */
export interface TrafficPeer {
  id: string
  label: string
  online: boolean
  active: boolean
  rxBytes: number
  txBytes: number
  /** A path straight to the device; otherwise relay names the region carrying it. */
  direct: boolean
  relay?: string
  exitNode: boolean
  lastHandshake?: string
  /** Absent means not measured rather than unreachable, so nothing reports a device that
   *  was never probed as slow. */
  latencyMs?: number
}

interface TrafficTotals {
  proxyUp: number
  proxyDown: number
  refused: number
  failed: number
}

/** What the agent has carried recently, and where. The series is the agent's own: the
 *  dashboard stops polling while its tab is hidden, so a history kept here would go
 *  blank exactly when the page is left open. */
export interface TrafficView {
  intervalSec: number
  windowSec: number
  points: TrafficPoint[]
  current: TrafficPoint
  totals: TrafficTotals
  peers: TrafficPeer[]
  destinations: TrafficDestination[]
  /** What the destination cap left unnamed, and how many distinct destinations are
   *  summed into it. A list silently cut short reads as a complete one. */
  other?: TrafficDestination
  folded?: number
}

/** Which breakdown of the traffic window to draw. Each is a finer cut of the one before
 *  it: a device is reached through a connection, which carries destinations, which are
 *  reached on ports. */
export type TrafficLane = 'devices' | 'connections' | 'destinations' | 'ports'

/** One key's rates across the window, oldest first.
 *
 *  A null is an interval that could not be measured -- the key was absent at one end of it,
 *  or its counters reset -- and a chart breaks its line there rather than drawing a floor
 *  nobody observed. It is the same fact TrafficPoint carries as its gap flag. */
export interface TrafficSeries {
  key: string
  label: string
  /** The aside beside the label: "relay nyc", "wireguard", "tcp". */
  detail?: string
  /** The connection carrying this key and the device it belongs to, each absent where the
   *  counter that measured the bytes could not attribute them. They are what a lane is
   *  filtered by. */
  via?: string
  peer?: string
  up: (number | null)[]
  down: (number | null)[]
}

/** One lane of the traffic window, split by what that lane names. Served per lane because
 *  the series are most of the payload and only one lane is ever on screen. */
export interface TrafficBreakdown {
  lane: TrafficLane
  intervalSec: number
  windowSec: number
  series: TrafficSeries[]
  /** How many keys are not named individually, whether summed into the trailing series or
   *  dropped by the agent's cap. A list silently cut short reads as a complete one. */
  folded?: number
  /** Why this lane holds nothing, absent when it holds what it can. It is the difference
   *  between a network that is quiet and one the agent cannot see. */
  unmeasured?: string
}

/** One ready-to-run command. Rendered by the agent, never assembled here: a shell
 *  command built in the UI is a shell command nothing tests. */
interface Snippet {
  id: string
  label: string
  description: string
  command: string
}

interface ProxyCounters {
  opened: number
  active: number
  refused: number
  failed: number
  bytesUp: number
  bytesDown: number
}

export interface ProxyView {
  enabled: boolean
  listening?: string
  nodeUp: boolean
  scope: string
  scopeCarries: string
  resolveVia: string
  resolveExplains: string
  requiresPassword: boolean
  error?: string
  configuredAddr: string
  movedFromConfig: boolean
  socksUrl?: string
  httpUrl?: string
  pacUrl?: string
  counters: ProxyCounters
  capability: Capability
  snippets: Snippet[]
}

/** What a rule decides when it matches. Mirrors access.Action. */
export type AccessAction = 'allow' | 'deny'

/** The transport a rule is about. The empty string is every transport, which is why it is
 *  a value here rather than an absent field. Mirrors access.Protocol. */
export type AccessProtocol = '' | 'tcp' | 'udp'

/**
 * One permission on one proxy instance. Mirrors access.Rule.
 *
 * Order is the meaning: the first rule that matches decides, and anything no rule matches is
 * refused. That is why the rules travel as an array and are written back whole rather than
 * one at a time — a partial write would have to say where each rule goes, and getting that
 * wrong moves a refusal below the grant it was written to except.
 */
export interface AccessRule {
  id: string
  action: AccessAction
  /** The connection this rule is about, by id. Absent is any connection; '-' is this
   *  machine's own network. */
  tunnel?: string
  /** A label-anchored glob matched against the name a program asked for, before it is
   *  resolved. Absent matches any host. */
  host?: string
  /** Matched against the address that name resolved to. Absent matches any address. */
  cidr?: string
  /** Single ports and inclusive ranges ('5432', '8000-8100'). Absent covers every port; an
   *  empty array is refused, because the two readings of it are opposites. */
  ports?: string[]
  protocol?: AccessProtocol
  /** The user's own words about why this rule exists, carried through to the reason a
   *  decision reports. */
  note?: string
}

/** This machine's own network, as a rule names it. Without a rule carrying it an instance
 *  cannot reach localhost or the LAN. Mirrors access.ThisMachine. */
export const THIS_MACHINE = '-'

/**
 * One proxy instance: what was granted to it, and what it is doing. Mirrors
 * httpapi.ProxyInstanceView.
 *
 * `settings` carries the stored fields under the keys the instance schema names, so the
 * instance form is rendered from the schema with no per-instance code here.
 */
export interface ProxyInstanceView {
  id: string
  name: string
  slug: string
  enabled: boolean
  /** Whether this instance may be removed. Served, so a client never holds its own idea of
   *  which one is load-bearing. */
  removable: boolean
  settings: Record<string, unknown>
  rules: AccessRule[]
  /** What those rules amount to, one sentence each. Computed by the agent so the dashboard,
   *  the menu bar and the command line cannot describe one instance's grants differently. */
  reach: string[]
  listening?: string
  /** The socket beside the port, where the platform has one. */
  localSocket?: string
  configuredAddr: string
  movedFromConfig: boolean
  requiresPassword: boolean
  error?: string
  socksUrl?: string
  httpUrl?: string
  /** Where a browser fetches the auto-configuration script. Only the instance the command
   *  line reaches has one: the script answers for that instance's grants, so offering it
   *  from another card would point a browser at a different set of permissions. */
  pacUrl?: string
  /** The ready-to-run ways of pointing a program at this instance. The ones that go back
   *  through app-tail itself are offered for that same instance only, so a narrow instance
   *  carries fewer of them than the default one. */
  snippets: Snippet[]
  counters: ProxyCounters
  capability: Capability
}

/** What adding an instance needs. Mirrors httpapi.ProxyInstanceSpec.
 *
 *  `slug` and `listenAddr` are optional because both are derivable: the agent makes a handle
 *  out of the name and takes the next port nothing has asked for. A new instance is granted
 *  nothing, so it reaches nothing until somebody says otherwise. */
export interface ProxyInstanceSpec {
  name: string
  slug?: string
  listenAddr?: string
}

/** The instance form's vocabulary, plus the words a rule is written in. Mirrors
 *  httpapi.ProxySchemaView. */
export interface ProxySchemaView {
  fields: SettingFieldSchema[]
  groups: SettingGroupInfo[]
  modules: FeatureModuleInfo[]
  /** Served rather than listed here, so this bundle never offers a verdict or a transport
   *  the agent it is talking to refuses the moment it is saved. */
  actions: AccessAction[]
  protocols: AccessProtocol[]
}

/** What one instance would do with a destination, decided without dialling it. Mirrors
 *  httpapi.ProxyTestResult.
 *
 *  `rule` and `ruleIndex` are the point: rule order is the whole difficulty of a permission
 *  model, and 'refused' without 'by which line' leaves somebody editing rules and guessing
 *  which one they are actually changing. */
export interface ProxyTestResult {
  address: string
  allowed: boolean
  /** Both absent when nothing could work out where the destination is, which is a third
   *  answer rather than a refusal. */
  resolved?: string
  tunnel?: string
  tunnelName?: string
  rule?: string
  /** One-based, as the rules table numbers its rows. Zero when no rule matched. */
  ruleIndex?: number
  reason: string
}

/** One command that points this whole machine at the proxy, for the platforms app-tail
 *  will not write the setting on itself. The per-program ways live in ProxyView.snippets;
 *  they are not repeated here. */
interface SystemProxyCommand {
  label: string
  command: string
}

/** This machine's own proxy configuration. `enabled` is the switch; `applied` is whether
 *  the machine is actually pointing at the proxy — they differ whenever the platform,
 *  the proxy's state, or another program got in the way. */
export interface SystemProxyView {
  enabled: boolean
  platform: string
  supported: boolean
  applied: boolean
  autoConfigUrl?: string
  managed: boolean
  manual: SystemProxyCommand[]
  capability: Capability
}

/** The automatic port mapping module. `stored` counts assignments that persist,
 *  including ones for devices not currently mapped: it is what says whether forgetting
 *  would do anything. */
export interface AutoMapView {
  enabled: boolean
  ports: number[]
  limit: number
  mapped: number
  stored: number
  truncated: number
  reason?: string
}

/** What the log module is holding. `events` is what it has now and `eventsRecorded` is
 *  everything it has ever taken, so the two together say how far the window has moved;
 *  `dropped` above zero means the log has holes and the screen has to say so. */
export interface TelemetryStats {
  events: number
  eventsRecorded: number
  eventCapacity: number
  dropped: number
  oldest?: string
  retentionSec: number
}

/** The log module. `switchKey` names the setting that turns recording on, so a screen that
 *  finds it off can offer that control without knowing anything module-specific. */
export interface TelemetryView {
  enabled: boolean
  switchKey: string
  reason?: string
  stats: TelemetryStats
  codes: string[]
  categories: string[]
  severities: string[]
  capability: Capability
}

/** One thing the agent did. `fields` are the small named values behind the sentence — a
 *  connection, a port, a setting key — and are what a search matches besides the message. */
export interface TelemetryEvent {
  seq: number
  at: string
  code: string
  category: string
  severity: string
  message: string
  fields?: Record<string, string>
}

/** One page of the log, newest first. `next` is empty at the end of the log, which is what
 *  a caller checks rather than comparing the row count to the limit: a page exactly the
 *  size of the limit may or may not be the last one. */
export interface TelemetryPage {
  events: TelemetryEvent[]
  next?: string
  total: number
}

/** The filter a log page is asked for. Every field narrows, and an empty one matches
 *  everything. */
export interface TelemetryQuery {
  categories?: string[]
  severities?: string[]
  codes?: string[]
  text?: string
  limit?: number
  cursor?: string
}

/** telemetryQuery renders a filter as the query string the agent parses. A word it does not
 *  know is refused there rather than ignored, which is what keeps a mistyped filter from
 *  showing the whole log as a narrowed one. */
function telemetryQuery(query: TelemetryQuery): string {
  const params = new URLSearchParams()
  for (const category of query.categories ?? []) params.append('category', category)
  for (const severity of query.severities ?? []) params.append('severity', severity)
  for (const code of query.codes ?? []) params.append('code', code)
  if (query.text) params.set('q', query.text)
  if (query.limit !== undefined) params.set('limit', String(query.limit))
  if (query.cursor) params.set('cursor', query.cursor)
  const rendered = params.toString()
  return rendered === '' ? '' : `?${rendered}`
}

/** The privileged helper that creates the network interface. `design` is whether this
 *  platform uses one at all; the rest describe the one on this machine. */
interface InterfaceHelper {
  design: boolean
  installable: boolean
  installed: boolean
  running: boolean
  version?: string
  problem?: string
  socket?: string
}

/** The network-interface mode. `mode` is the stack the node is really on and
 *  `configured` the one the settings ask for; they disagree in the case this card exists
 *  for, where the node asked for the interface and fell back. `ready` answers only
 *  "would switching work right now", which is what the one-click control needs and is a
 *  different question from the `capability` sentence beside it. */
export interface InterfaceView {
  enabled: boolean
  mode: string
  configured: string
  inForce: boolean
  fallback?: string
  ready: boolean
  blocker?: string
  interface?: string
  helper: InterfaceHelper
  conflict?: string
  missing?: string
  leftovers?: string[]
  undo?: string[]
  capability: Capability
}

/** One setting app-tail keeps on the tailnet node itself, seen from both sides.
 *  `stored` is what this app holds; `live` is what the node reports, absent until it
 *  has reported anything at all. */
export interface PrefFieldView {
  key: string
  label: string
  /** null is on the wire, not a mistake: an empty list setting marshals from a nil Go
   *  slice, so a field nobody has set arrives as null rather than as []. */
  stored: boolean | string | number | string[] | null
  live?: boolean | string | number | string[] | null
  inForce: boolean
}

/** The settings whose value lives on the tailnet node rather than on this machine.
 *  `conflict` names the ones app-tail stopped applying because something outside it
 *  kept changing them back. */
export interface PrefsView {
  nodeUp: boolean
  known: boolean
  /** Absent when an older agent sends null for the empty case, so every read guards it. */
  fields: PrefFieldView[] | null
  conflict?: string[]
  capability: Capability
}

/** The login item. `problem` describes one that is installed and will not start app-tail
 *  correctly — it starts it with the wrong rights for the current network mode, or names a
 *  binary that has moved. The switch reads as on either way, so the fault travels with it. */
export interface AutostartView {
  enabled: boolean
  problem?: string
}

/** One device the tailnet offers as an approved exit node. `display` is the name with the
 *  place beside it, rendered by the agent so a picker and a log line read the same. */
export interface ExitNodeCandidate {
  id: string
  label: string
  display: string
  online: boolean
  country?: string
  city?: string
  current: boolean
}

/** The tailnet's own recommendation. An empty `id` with a `reason` is the ordinary answer
 *  on a tailnet whose exit nodes are all self-hosted — not a failure. */
export interface ExitNodeSuggestion {
  id?: string
  label?: string
  country?: string
  city?: string
  reason?: string
}

/** Where this device's other traffic leaves through. `current` is what app-tail asked
 *  for; `liveId`/`liveOnline` are what the tailnet node reports is actually carrying it —
 *  they differ while a change is in flight or the chosen device is away. */
export interface ExitNodeView {
  /** The connection whose devices these are: a device id only means anything on the
   *  network that issued it. */
  tunnelId: string
  enabled: boolean
  rotating: boolean
  current?: string
  currentLabel?: string
  liveId?: string
  liveOnline: boolean
  reason?: string
  /** When the rotation schedule moves on, RFC 3339. Absent when nothing is scheduled. */
  nextChange?: string
  warning: string
  candidates?: ExitNodeCandidate[]
  capability: Capability
}

/** Both directions of subnet routing. `advertised` is what this device offers to carry
 *  and `approved` is what the tailnet actually grants it — the gap between them is the
 *  usual reason a route does nothing, since advertising is a request an admin has to
 *  approve before any traffic arrives. */
export interface RoutesView {
  /** The connection this describes. Routing belongs to one private network, so the page
   *  showing it beside a connection is told which one rather than assuming. */
  tunnelId: string
  enabled: boolean
  accepting: boolean
  reaching?: string[]
  advertised?: string[]
  approved?: string[]
  serving: boolean
  carried: number
  refused: number
  bytesIn: number
  bytesOut: number
  error?: string
  capability: Capability
}

/** Where each connected network is reachable from this machine.
 *
 *  Two networks can carry the same addresses, and only one of them can be reached at
 *  them. `mode` is `report` while this build only says so: nothing is re-addressed, so a
 *  page renders the conflict as something to act on rather than as something it can fix. */
export interface FabricView {
  mode: string
  /** The address space a moved network would be presented from. */
  pool?: string[]
  networks?: FabricNetwork[]
  /** One entry per contested range rather than per connection, so three connections
   *  claiming one range is one thing to say rather than three. */
  conflicts?: FabricConflict[]
  /** Connections whose networks could not be read, with the reason. A range missing from
   *  the report is a collision reported as none, so it is shown rather than dropped. */
  unread?: FabricUnread[]
  /** What the operating system calls the interface carrying these networks, absent while
   *  nothing carries them. */
  interface?: string
  /** The interface up and carrying traffic, which is a separate question from `mode`: the
   *  mode is what was asked for and this is what is happening. */
  running: boolean
  /** The largest packet the interface carries: the smallest of the connected networks'
   *  own, because a datagram cannot be split the way a byte stream can. */
  mtu?: number
  /** The ranges this machine is sending to the interface right now. */
  routes?: string[]
  /** What each connection has carried. An entry with no `tunnelId` is what was refused
   *  because no connection carried the address at all. */
  carried?: FabricCarried[]
  /** Why the interface is not carrying what it was asked to. */
  error?: string
  capability: Capability
}

/** Where this machine's internet traffic leaves through.
 *
 *  `mode` is the setting and `carrying` is what is happening, and the gap between the two
 *  is the whole reason this is read rather than taken from the settings: a connection
 *  chosen to carry the traffic that is down, or up with nothing at the far end routing
 *  traffic on, leaves a setting saying "through my VPN" over traffic going nowhere. */
export interface EgressView {
  mode: string
  /** The connection chosen to carry it. Present whenever one is stored, including while
   *  the traffic goes out directly -- a remembered choice is what lets someone switch back
   *  without picking again. */
  tunnelId?: string
  tunnelName?: string
  carrying: boolean
  /** Why it is not carrying, in the connection's own words. */
  reason?: string
  /** What choosing this connection does not cover, stated up front rather than
   *  discovered. */
  limits?: string[]
  /** How the members carry it between them: `spread` across them, or `cascade` through all
   *  of them in order. Present only while several connections carry it. */
  shape?: string
  /** The connections carrying the traffic between them, one row each, present only while
   *  several do. Each carries its own answer: spread, one member being down moves the
   *  destinations that were on it and leaves the rest alone; chained, one being down stops
   *  the whole route at that hop. */
  members?: EgressMember[]
  /** The traffic is being held here rather than sent out over this machine's own network,
   *  because the connections chosen to carry it cannot. */
  held?: boolean
  /** The promise is on: nothing leaves over this machine's own network whatever happens to
   *  the connection carrying it. Present only while one connection carries the traffic,
   *  which is the one mode the switch is read in. It is the setting rather than the
   *  outcome -- `held` is true only at the moments it is stopping traffic. */
  killSwitch?: boolean
}

/** One connection out of the set carrying this machine's internet traffic. */
export interface EgressMember {
  tunnelId: string
  tunnelName?: string
  /** The connection the traffic leaves through, which only a chain has: the last hop, the
   *  one whose address the internet sees. */
  exit?: boolean
  carrying: boolean
  /** This hop has not started because the one before it in the chain is not carrying yet.
   *  Every start of a chain passes through it, so it is not a failure. */
  waiting?: boolean
  /** Why it is not carrying, in the connection's own words. */
  reason?: string
  limits?: string[]
}

/** What one connection carried across the interface. */
export interface FabricCarried {
  tunnelId?: string
  name?: string
  /** Flows handed on, and flows turned away. */
  flows: number
  refused: number
  /** Bytes this machine put into the network, and what came back. */
  sent: number
  received: number
  /** Flows open right now. */
  holding: number
}

/** One network a connection carries. `presentedAs` is empty both when the network keeps
 *  its own addresses and when it has to move with nothing free to move it to; `reason` is
 *  what tells those apart, set exactly when it cannot be reached at its own addresses. */
export interface FabricNetwork {
  tunnelId: string
  tunnelName?: string
  prefix: string
  presentedAs?: string
  reason?: string
}

export interface FabricConflict {
  prefix: string
  /** The connection reachable at the range as it stands, absent when this machine itself
   *  is the one on that network. */
  holder?: string
  holderName?: string
  claimants?: FabricClaimant[]
  detail: string
}

export interface FabricClaimant {
  tunnelId: string
  name?: string
}

export interface FabricUnread {
  tunnelId: string
  name?: string
  error: string
}

/** One accepted network and the devices carrying it that answered a probe. An empty
 *  `via` is the state worth seeing: the route is in the netmap and nothing answers. */
interface RouteCheckEntry {
  prefix: string
  via?: string[]
  reachable: boolean
}

export interface RouteCheckResult {
  routes: RouteCheckEntry[]
  reason?: string
}

/** What a matching routing rule does with the destination. Mirrors routing.Action. */
export type RoutingAction = 'via' | 'direct' | 'block'

/**
 * One per-destination exception to where internet traffic leaves.
 *
 * `host` and `cidr` are two halves of one destination and both are matched when both are
 * given. A rule states at least one of them: one that stated neither would cover every
 * destination, which is the internet traffic setting rather than an exception to it.
 */
export interface RoutingRule {
  id: string
  action: RoutingAction
  /** The connection to send the destination through, by id. Required by 'via' and
   *  meaningless to the other two actions. */
  tunnel?: string
  /** A label-anchored glob matched against the name that was asked for. */
  host?: string
  /** Matched against the address. */
  cidr?: string
  note?: string
}

/** One connection a rule may name. `running` is served because a rule may name one that is
 *  not: the rule stays the rule, and those destinations are refused rather than quietly
 *  sent out another way. */
export interface RoutingTunnel {
  id: string
  name: string
  running: boolean
}

/** The whole rule list plus the vocabulary to render it. Mirrors httpapi.RoutingView. */
export interface RoutingView {
  rules: RoutingRule[]
  /** One sentence per rule, in the same order, with every connection named as a person
   *  calls it. Rendered by the agent so every surface states a rule identically. */
  describe: string[]
  /** The rules that decide nothing on the network interface, because an earlier rule
   *  already covers their range. They still apply on the proxy path. */
  shadowed?: string[]
  actions: RoutingAction[]
  tunnels: RoutingTunnel[]
  limits?: string[]
  capability: Capability
}

/** Which way one destination goes and which rule said so. `decided` false is the ordinary
 *  answer: no rule names it, so it leaves the way the internet traffic setting says. */
export interface RoutingCheckResult {
  destination: string
  decided: boolean
  action?: RoutingAction
  tunnel?: string
  tunnelName?: string
  rule?: string
  ruleIndex?: number
  reason: string
}

/** What tailnet lock means for this device. `signed` false while `enabled` is the state
 *  this exists for: the node connects, reports Running, and the control plane strips
 *  every peer from its netmap until an administrator signs it. */
export interface LockView {
  enabled: boolean
  signed: boolean
  nodeKey?: string
  lockKey?: string
  signCommand?: string
  trusted?: LockKeyView[]
  canSign: boolean
  visible: number
  filtered?: LockPeerView[]
  head?: string
  error?: string
  capability: Capability
}

interface LockKeyView {
  id: string
  kind?: string
  votes: number
  self: boolean
  label?: string
}

/** A device lock removed from this one's view of the tailnet: it exists, it is in the
 *  netmap, and it is unreachable however the tailnet's access rules read. */
interface LockPeerView {
  id: string
  name: string
  nodeKey: string
  ips?: string[]
}

export interface LockUpdate {
  hash: string
  change: string
}

/** What the tailnet publishes beside what this machine actually resolves with. The gap
 *  between the two is the whole question: `machine` is absent in the mode app-tail ships
 *  in, and `machineReason` is why — not a failed read. */
export interface DNSView {
  enabled: boolean
  using: boolean
  magicDNS: boolean
  resolvers?: string[]
  searchDomains?: string[]
  routes?: DNSRouteView[]
  records?: DNSRecordView[]
  machine?: DNSMachineView
  machineReason?: string
  exitNodeResolving: boolean
  exitNodeLabel?: string
  /** The machine-wide resolver, which is a different feature from the tailnet one above.
   *  Absent from an agent older than it: a client reads that as the feature not being
   *  there rather than as a module reporting itself off. */
  system?: DNSSystemView
  error?: string
  capability: Capability
}

/** What every program on this machine resolves through. `enabled` is the switch and
 *  `applied` this machine actually pointed at app-tail; they differ whenever the platform,
 *  the administrator rights or the chosen profile got in the way, and collapsing them is
 *  what turns a stated limitation into a bug report. Mirrors httpapi.DNSSystemView. */
export interface DNSSystemView {
  enabled: boolean
  applied: boolean
  profile: string
  profileLabel?: string
  servers?: string[]
  /** How each server is reached -- 'plain', 'tls', 'https' -- which is the one thing the
   *  address alone does not make obvious. */
  protocols?: string[]
  listen?: string
  base?: DNSBaseView
  localSuffixes?: string[]
  retryOnNxdomain: boolean
  /** Whether the machine could carry this right now, and what stands in the way when it
   *  cannot. `needsSetup` is the one blocker a button can fix. */
  ready: boolean
  blocker?: string
  needsSetup: boolean
  /** The chosen profile answering nothing at all: every name fails while the network's own
   *  sign-in page still resolves, which is what a captive portal looks like from here. */
  unreachable?: string
  /** This network answering plain DNS on its own behalf, checked only for a profile that
   *  has a plain resolver in it. It is the one state where everything looks like it worked
   *  and none of the queries reached the resolver that was picked. */
  intercepted?: string
  /** How the resolvers in this profile that are named by hostname were turned into
   *  addresses, and absent when none of them are. An encrypted bootstrap decides the address
   *  by certificate; the fallback to this network's own resolvers lets the network decide it,
   *  so which one happened is stated rather than assumed. */
  bootstrap?: string
  /** That fallback having happened without being asked for. Choosing this network's
   *  resolvers deliberately is a decision, not a fault. */
  bootstrapDegraded?: boolean
  queries: DNSSystemStats
  error?: string
  capability: Capability
}

/** What this machine would resolve with if app-tail were not here. Names belonging to this
 *  network still go there. */
interface DNSBaseView {
  nameservers?: string[]
  searchDomains?: string[]
}

interface DNSSystemStats {
  total: number
  toProfile: number
  toLocal: number
  answered: number
  failed: number
  /** The subset of `answered` a blocklist stopped, so the counters still sum to `total`. */
  blocked: number
}

/** Name blocking as every surface reads it. `own` and `system` are separate switches
 *  reaching different things — what app-tail resolves for itself, and what this machine
 *  resolves — and neither implies the other. Mirrors httpapi.DNSBlockView. */
export interface DNSBlockView {
  enabled: boolean
  own: boolean
  system: boolean
  /** What a blocked name is answered with: 'nxdomain', 'sinkhole' or 'refused'. */
  answer: string
  /** How many names the compiled matcher holds, and when it was built. */
  rules: number
  lists?: DNSBlockListView[]
  compiledAt?: string
  /** When a pause ends. Absent while blocking is running. */
  pausedUntil?: string
  refreshHours: number
  nextRefresh?: string
  /** Queries this machine's resolver refused, which stays zero while the machine-wide
   *  resolver is off however much app-tail blocked for itself. */
  blocked: number
  allow?: string[]
  deny?: string[]
  /** The machine-wide resolver's retry switch being on, which sends a blocked name to this
   *  network as well and so unblocks it. */
  retryOnNxdomain: boolean
  /** The curated levels, lowest first, and the one the lists switched on happen to be.
   *  `preset` is absent for a set of lists that is nobody's level. */
  presets?: DNSBlockPresetView[]
  preset?: string
  error?: string
  capability: Capability
}

/** One rung of the curated ladder: what it is called, what it blocks, and the shipped lists
 *  it switches on. Mirrors httpapi.DNSBlockPresetView. */
export interface DNSBlockPresetView {
  id: string
  name: string
  summary: string
  /** The rung to pick without reading the rest. Exactly one carries it. */
  recommended?: boolean
  lists: string[]
}

/** One catalog entry and what its downloaded copy contributed. `rules` beside `skipped` is
 *  what says whether a list is pulling its weight here or is mostly written for a browser. */
export interface DNSBlockListView {
  id: string
  /** Who publishes the list. The catalog is shown grouped by it; lists the user added
   *  share one group of their own. */
  provider: string
  name: string
  url: string
  format?: string
  builtIn: boolean
  enabled: boolean
  rules: number
  skipped: number
  bytes?: number
  /** When the copy on disk was last confirmed current, and what went wrong last time. A
   *  list carrying both is still blocking from a copy that has stopped being updated. */
  updatedAt?: string
  error?: string
  note?: string
}

/** Why one name is or is not blocked. `reason` covers the answers that are not about a
 *  list: blocking off, or paused. */
export interface DNSBlockCheckView {
  name: string
  blocked: boolean
  list?: string
  reason: string
}

/** Traffic inspection as every surface reads it. `names` and `destinations` are separate
 *  switches reaching different things — what a program asked for, which only the proxy
 *  knows, and the address a connection is bound for, which every path knows. Mirrors
 *  httpapi.IPSView. */
export interface IPSView {
  enabled: boolean
  /** What a match leads to: 'detect' records it and carries the connection, 'prevent'
   *  refuses it. */
  mode: string
  names: boolean
  destinations: boolean
  /** The signal that reads a run of connections rather than any one of them. It matches
   *  against no list, so it is on or off independently of `rules` being zero. */
  anomaly: boolean
  /** Whether the opening bytes of a connection are read, which is where the name lives on
   *  traffic dialled straight at an address, and whether the software that sent them is noted
   *  alongside. The second needs the first. */
  handshake: boolean
  fingerprints: boolean
  /** Whether those same opening bytes are read against the user's own byte patterns, and how
   *  many of those are in force. The patterns themselves are never carried here: they are
   *  often the thing being watched for a leak of. */
  payload: boolean
  signatures: number
  /** How many entries the compiled matcher holds, and when it was built. */
  rules: number
  compiledAt?: string
  /** Every catalog entry and what its downloaded copy contributed, how often they are
   *  re-downloaded, and when the oldest enabled copy is next due. */
  feeds?: IPSFeedView[]
  refreshHours: number
  nextRefresh?: string
  /** The curated levels, lowest first, and the one the feeds switched on happen to be.
   *  `preset` is absent for a set of feeds that is nobody's level. */
  presets?: IPSPresetView[]
  preset?: string
  /** Entries the matcher could make nothing of. They are dropped rather than refused, so
   *  without this one that is neither a name nor an address would never match and nothing
   *  would say why. */
  skipped: number
  /** When a pause ends. Absent while inspection is running. */
  pausedUntil?: string
  /** Connections the rules matched, and how many of those were stopped. The two differ by
   *  every match that landed while the mode was detect. */
  matched: number
  refused: number
  /** Runs of connections that read as unusual. Counted apart from `matched` because they
   *  name no entry anybody wrote: the two answer different questions. */
  anomalies: number
  allow?: string[]
  deny?: string[]
  /** The newest matches first, held in the agent rather than read from the activity log:
   *  that log is off until a user turns it on, and this card works on a fresh install. */
  recent?: IPSDetectionView[]
  /** Destinations something keeps going back to on a rhythm, most regular first. Kept apart
   *  from `recent` because they are an observation and nothing else: on an ordinary machine
   *  the regular things are chat clients, backups and certificate checks, so none of them is
   *  ever refused or counted as a finding. */
  beacons?: IPSBeaconView[]
  /** What the last round of downloads ended with. Absent when it ended cleanly. */
  error?: string
  /** Opening encrypted connections, which is the one part of inspection that changes what the
   *  program at the far end sees. */
  intercept: IPSInterceptView
  capability: Capability
}

/** The state of opening encrypted connections. It carries no key and never will: what is here
 *  is the public certificate's path and its fingerprint, which are what a user checks against
 *  their own trust store. Mirrors httpapi.IPSInterceptView. */
export interface IPSInterceptView {
  /** Which connections are opened: 'off', 'only' the ones named, or everything 'except' the
   *  ones named. `agreed` is whether the person using this machine has said they understand
   *  what opening a connection means; without it nothing is opened whatever the mode says. */
  mode: string
  agreed: boolean
  /** Every setting asks for interception: the module, the agreement and a mode that is not
   *  off. Removing the root is refused while it is. */
  on: boolean
  /** Every condition met and a root held: the one field that answers whether this is
   *  happening right now. */
  running: boolean
  /** How many entries the list in force holds, and whether that list is the one app-tail
   *  ships rather than one the user wrote. */
  destinations: number
  shipped: boolean
  /** Where the certificate to install is written, its SHA-256, and when it stops being
   *  usable. The fingerprint is what a user compares against what their trust store holds. */
  certPath: string
  fingerprint?: string
  expires?: string
  /** What the root can sign for, as the end of a sentence beginning "This root can sign for". */
  rootScope?: string
  /** The list being intercepted reaches past what the root was made for, or the root has no
   *  limits at all, and the sentence saying so and what to do. */
  needsNewRoot: boolean
  newRootReason?: string
  /** The root is within thirty days of its end, or past it, and the sentence saying which and
   *  what to do. A root is never replaced on its own. */
  expiresSoon: boolean
  expired: boolean
  expiryWarning?: string
  /** Why the root's certificate could not be read, when it could not. */
  rootError?: string
  /** Whether this machine's trust store accepts the root right now, asked of the machine
   *  rather than remembered. It is how a user knows an install worked, and the only way to
   *  know a removal did. */
  installed: boolean
  /** The commands for this operating system, and what they do not cover. */
  install?: string
  remove?: string
  note?: string
  /** Connections opened, and connections stopped because they could not be. */
  opened: number
  failed: number
  /** Why interception is waiting for an administrator's approval, while it is. */
  awaitingApproval?: string
  /** The approvals file could not be read, so interception is refused until it can be. */
  approvalError?: string
}

/** One rung of the curated ladder: what it is called, what it matches, and the shipped feeds
 *  it switches on. Mirrors httpapi.IPSPresetView. */
export interface IPSPresetView {
  id: string
  name: string
  summary: string
  /** The rung to pick without reading the rest. Exactly one carries it. */
  recommended?: boolean
  feeds: string[]
}

/** One catalog entry and what its downloaded copy contributed. `rules` beside `skipped` is
 *  what says a feed's private and reserved ranges were left out: those ranges are in these
 *  files on purpose, and applying them would refuse the tailnet and the LAN. Mirrors
 *  httpapi.IPSFeedView. */
export interface IPSFeedView {
  id: string
  /** Who publishes the feed. The catalog is shown grouped by it; feeds the user added share
   *  one group of their own. */
  provider: string
  name: string
  url: string
  builtIn: boolean
  enabled: boolean
  rules: number
  skipped: number
  bytes?: number
  /** When the copy on disk was last confirmed current, and what went wrong last time. A feed
   *  carrying both is still matching from a copy that has stopped being updated. */
  updatedAt?: string
  error?: string
  note?: string
}

/** One feed of addresses. Built-in entries ship with the binary and can be neither edited nor
 *  deleted; they can be switched on and off like any other. */
export interface IPSFeed {
  id: string
  name: string
  url: string
  builtIn: boolean
}

/** One destination reached on a rhythm. Mirrors httpapi.IPSBeaconView. */
export interface IPSBeaconView {
  /** The device doing it, which for this machine's own traffic is this machine, and what it
   *  keeps going back to. */
  source: string
  addr: string
  /** The average gap between connections in seconds, and how much they vary as a fraction of
   *  it: nearer zero is more regular. */
  every: number
  jitter: number
  /** How many connections the rhythm was measured over, and when the first of them was. */
  count: number
  since: string
}

/** One match: what matched, where the connection was being carried, and whether it was
 *  stopped. Mirrors httpapi.IPSDetectionView. */
export interface IPSDetectionView {
  at: string
  signal: string
  value: string
  source: string
  reason: string
  where: string
  protocol?: string
  /** The device that asked, which only an inbound connection from the tailnet has. */
  peer?: string
  /** Which family of TLS software opened the connection, on a match read from the opening
   *  bytes with fingerprinting on. Nothing is ever matched on it. */
  fingerprint?: string
  refused: boolean
}

/** What the rules say about one destination. `matched` and `refused` are separate because in
 *  detect mode a destination matches and is still carried. */
export interface IPSCheckView {
  destination: string
  matched: boolean
  refused: boolean
  signal?: string
  value?: string
  source?: string
  reason: string
}

/** One downloadable list of names. Built-in entries ship with the binary and can be neither
 *  edited nor deleted; they can be switched on and off like any other. */
export interface Blocklist {
  id: string
  name: string
  url: string
  format?: string
  builtIn: boolean
}

/** One named set of resolvers. Built-in entries ship with the binary and can be neither
 *  edited nor deleted, which is what keeps a way back when a custom one is what broke
 *  resolution. */
export interface DNSProfile {
  id: string
  name: string
  servers?: string[]
  builtIn: boolean
}

/** One split-DNS suffix. An empty `resolvers` means the tailnet's own resolver answers
 *  for it, which is how a suffix is claimed without redirecting it anywhere. */
interface DNSRouteView {
  suffix: string
  resolvers?: string[]
}

interface DNSRecordView {
  name: string
  type?: string
  value: string
}

interface DNSMachineView {
  nameservers?: string[]
  searchDomains?: string[]
  matchDomains?: string[]
}

/** What this node can actually do with a device, as distinct from whether the control
 *  plane calls it online. The agent derives it; mirrors tsnode.PeerReach. */
export type PeerState = 'ready' | 'relayed' | 'no-path' | 'offline' | 'expired'

export interface PeerReach {
  state: PeerState
  reason?: string
}

export interface Peer {
  id: string
  hostName: string
  dnsName: string
  ips: string[]
  online: boolean
  os: string
  tags?: string[]
  /** Absent from an agent older than this field; callers must tolerate that rather
   *  than render "undefined" beside a device name. */
  reach?: PeerReach
}

export interface Preset {
  id: string
  name: string
  protocol: Protocol
  remotePort: number
  builtIn: boolean
}

/** TunnelType is what protocol one connection speaks. It is fixed when the connection is
 *  added, which is why nothing in the dashboard ever writes it. */
export type TunnelType = 'tailscale' | 'wireguard' | 'openvpn'

/** The one status vocabulary every kind of connection reports in. `off` is a state, not a
 *  fault: it is what a connection that is not meant to be up says about itself. */
export type TunnelState =
  | 'off'
  | 'starting'
  | 'needs-login'
  | 'connecting'
  | 'connected'
  | 'degraded'
  | 'failed'
  | 'stopping'

/**
 * TunnelView is one private network this app is attached to. Mirrors httpapi.TunnelView.
 *
 * `settings` carries the stored fields under the same keys the connection schema names,
 * which is what lets the connection form be rendered without a line of per-type code
 * here. Everything beside it is the live half, which the stored document does not hold.
 */
export interface TunnelView {
  id: string
  type: TunnelType
  typeLabel: string
  name: string
  slug: string
  enabled: boolean
  /** Whether this connection may be removed. Served, so a client never holds its own idea
   *  of which one is load-bearing. */
  removable: boolean
  /** Whether this connection can be built again now. Served for the same reason: the agent
   *  decides what it would refuse, so no client offers an action it will be told no for. */
  retryable: boolean
  settings: Record<string, unknown>
  state: TunnelState
  stateLabel: string
  /** Whether traffic can cross right now, which is not the same as `state` being
   *  'connected': a degraded connection still carries. */
  live: boolean
  detail?: string
  /** What this connection has carried and how long it has been up. Absent for a kind that
   *  counts nothing of its own -- a tailnet counts per device, and those figures are on the
   *  activity screen -- so a screen never prints a confident zero for an uncounted
   *  connection. */
  health?: TunnelHealth
  authUrl?: string
  addrs?: string[]
  names?: string[]
  /** What this connection does not carry, stated up front. Not errors, and never clear. */
  limits?: string[]
}

/**
 * TunnelHealth is one connection's own account of itself, beside the state word: it is what
 * separates a connection that is up and working from one that is up and carrying nothing,
 * since both report themselves connected.
 */
export interface TunnelHealth {
  /** Cumulative bytes since the connection was built, from this machine's point of view. */
  up: number
  down: number
  /** When the connection was built. A connection that keeps coming back with a short uptime
   *  is failing and being retried, which every other field reports as working. */
  since?: string
  /** When the two sides last agreed on keys. Absent for a kind with no handshake. */
  lastHandshake?: string
  /** Packets the connection's own outbound queue discarded to keep its delay and depth
   *  bounded. Absent while nothing was dropped, and always for a kind with no such queue. */
  dropped?: number
}

/**
 * TunnelSpec is what adding a connection needs: what kind of network it is and what to
 * call it. Mirrors httpapi.TunnelSpec.
 *
 * `slug` is optional because it is derivable: leaving it out has the agent make a DNS
 * label out of the name, so nobody has to invent "office-vpn" for a network they called
 * "Office VPN".
 */
export interface TunnelSpec {
  type: TunnelType
  name: string
  slug?: string
}

/** One kind of network a connection can be added as. Mirrors httpapi.TunnelTypeInfo. */
export interface TunnelTypeInfo {
  value: TunnelType
  label: string
}

/** The connection form's vocabulary: the fields, plus the sections and modules they name.
 *  Mirrors httpapi.TunnelSchemaView. */
export interface TunnelSchemaView {
  fields: SettingFieldSchema[]
  groups: SettingGroupInfo[]
  /** The modules these fields are gated on. They are switched on the installation rather
   *  than on the connection, so their values come from the settings document. */
  modules: FeatureModuleInfo[]
  /** The kinds an add menu offers. Served rather than listed here, so this bundle never
   *  offers a kind the agent it is talking to cannot bring up. */
  types: TunnelTypeInfo[]
}

/** The settings vocabulary the agent serves: the fields, plus the sections and modules
 *  those fields reference by id. Mirrors httpapi.SettingsSchemaView. */
interface SettingsSchemaView {
  fields: SettingFieldSchema[]
  groups: SettingGroupInfo[]
  modules: FeatureModuleInfo[]
}

/** One setting that was stored without taking effect, and why. */
export interface DeferredSetting {
  key: string
  label: string
  reason: string
}

interface SettingsResponse extends Settings {
  restartRequired: boolean
  // nodeRestart is a node-identity change the agent can apply in place via
  // /api/restart; uiRelisten is a dashboard-address change that only a full
  // process restart can move; appRestart is a setting the process reads once at
  // start, which is stored now and honoured on the next one; adminRestart is a change
  // needing administrator rights this process does not hold, which on Windows are taken
  // by starting again with a prompt. adminRelaunch says the agent is restarting itself now
  // to take them, so the page goes away and comes back.
  nodeRestart: boolean
  uiRelisten: boolean
  appRestart: boolean
  adminRestart: boolean
  adminRelaunch: boolean
  // deferred is present only when a setting the tailnet node holds was stored while
  // the node was down, so a save is never reported as in force when it is not.
  deferred?: DeferredSetting[]
}

/** A one-click ACL bootstrap request. The OAuth client is used once by the agent
 *  and never stored; it lives only in this component's state until sent. */
export interface PolicyBootstrapRequest {
  clientId: string
  clientSecret: string
  tailnet?: string
  tags?: string[]
  owners?: string[]
  grantDsts?: string[]
  grantIps?: string[]
}

/** What a bootstrap would change (preview) or changed (apply). */
export interface PolicyPlanView {
  summary: string
  addTagOwner: boolean
  addGrant: boolean
  changed: boolean
  notes?: string[]
}

/** Details the server sends with a 409 so the UI can name the other forward. */
interface Conflict {
  endpoint: string
  forwardId: string
  name?: string
}

/** ApiError carries the server's status and message instead of a bare string, so
 *  callers can distinguish a validation problem from a conflict. */
export class ApiError extends Error {
  readonly status: number
  readonly conflict: Conflict | undefined
  /** The rejected input's key, when the agent named one. A settings form puts the
   *  complaint on that control rather than in a banner above a collapsed section. */
  readonly field: string | undefined

  constructor(status: number, message: string, conflict?: Conflict, field?: string) {
    super(message)
    this.name = 'ApiError'
    this.status = status
    this.conflict = conflict
    this.field = field
  }

  get isConflict(): boolean {
    return this.status === 409
  }

  get isValidation(): boolean {
    return this.status === 400
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const session = sessionToken()
  let response: Response
  try {
    response = await fetch(path, {
      ...init,
      headers: {
        ...(init?.body === undefined ? {} : { 'Content-Type': 'application/json' }),
        ...(session === undefined ? {} : { Authorization: `Bearer ${session}` }),
        ...init?.headers,
      },
    })
  } catch (cause) {
    // A dead agent is the single most common failure here, and it looks nothing
    // like a rejected request, so it gets its own status.
    throw new ApiError(0, `cannot reach the app-tail agent (${String(cause)})`)
  }

  // The agent answers 401 for one reason only: this page holds no session it accepts.
  // That is true of every page at once, so the whole app is signed out here rather than
  // each card reporting it; the request still fails below like any other refusal.
  if (response.status === 401) {
    markSignedOut(
      session === undefined
        ? 'this browser has not been signed in to app-tail'
        : 'the agent no longer accepts the session this browser holds: it expired, or every session was revoked',
    )
  }

  if (response.status === 204) {
    return undefined as T
  }

  const text = await response.text()
  let body: unknown = undefined
  if (text.length > 0) {
    try {
      body = JSON.parse(text)
    } catch {
      if (!response.ok) {
        throw new ApiError(response.status, text.slice(0, 300))
      }
      throw new ApiError(response.status, `the agent returned a non-JSON response for ${path}`)
    }
  }

  if (!response.ok) {
    const envelope = body as { error?: string; conflict?: Conflict; field?: string } | undefined
    throw new ApiError(
      response.status,
      envelope?.error ?? `request failed with status ${response.status}`,
      envelope?.conflict,
      envelope?.field,
    )
  }
  return body as T
}

export const api = {
  status: () => request<Status>('/api/status'),
  login: () => request<{ authURL: string; backendState: string }>('/api/login', { method: 'POST' }),
  /** The login already in progress, without starting another. */
  loginUrl: () =>
    request<{ authURL: string; backendState: string }>('/api/login/url', { method: 'POST' }),
  logout: () => request<{ backendState: string }>('/api/logout', { method: 'POST' }),
  restart: () => request<{ backendState: string }>('/api/restart', { method: 'POST' }),
  // The whole process, not the node. The answer arrives before the restart begins,
  // because the process serving it is the one going away.
  restartApp: () => request<{ restarting: boolean }>('/api/restart-app', { method: 'POST' }),
  /**
   * Whether the agent is answering at all.
   *
   * This is the probe a page waits on while the agent restarts, and it deliberately does
   * not go through `request`: /healthz answers 503 whenever the tailnet node is down, and
   * a node that is down is the ordinary state of a machine that is not signed in. Reading
   * that as "still restarting" would leave the page waiting forever on an agent that came
   * back perfectly well. Only fetch itself rejecting means nothing is listening yet.
   */
  reachable: async (): Promise<boolean> => {
    try {
      await fetch('/healthz', { method: 'GET' })
      return true
    } catch {
      return false
    }
  },
  tunSetup: () => request<{ restartNeeded: boolean }>('/api/tun/setup', { method: 'POST' }),
  // No body on purpose: the agent approves what it has pending and never takes a list from a
  // page, so nothing a page sends can widen what the root helper is allowed to change.
  approveNetworkChanges: () => request<Approvals>('/api/tun/approve', { method: 'POST' }),
  peers: () => request<{ peers: Peer[] }>('/api/peers').then((r) => r.peers),

  forwards: () => request<{ forwards: Forward[] }>('/api/forwards').then((r) => r.forwards),
  createForward: (spec: ForwardSpec) =>
    request<Forward>('/api/forwards', { method: 'POST', body: JSON.stringify(spec) }),
  updateForward: (id: string, spec: ForwardSpec) =>
    request<Forward>(`/api/forwards/${encodeURIComponent(id)}`, {
      method: 'PUT',
      body: JSON.stringify(spec),
    }),
  deleteForward: (id: string) =>
    request<void>(`/api/forwards/${encodeURIComponent(id)}`, { method: 'DELETE' }),
  toggleForward: (id: string, enabled: boolean) =>
    request<Forward>(`/api/forwards/${encodeURIComponent(id)}/toggle`, {
      method: 'POST',
      body: JSON.stringify({ enabled }),
    }),
  suggestPort: (protocol: Protocol, target: string, bindAddr?: string) => {
    const params = new URLSearchParams({ protocol, target })
    if (bindAddr) params.set('bindAddr', bindAddr)
    return request<{ port: number }>(`/api/forwards/suggest-port?${params}`).then((r) => r.port)
  },

  tunnels: () => request<{ tunnels: TunnelView[] }>('/api/tunnels').then((r) => r.tunnels),
  // The served schema, not a bundled copy: which fields a connection has depends on its
  // type and on what this build can bring up, neither of which this page can know.
  tunnelSchema: () => request<TunnelSchemaView>('/api/tunnels/schema'),
  // Devices are asked for per connection because a device id only means something on the
  // network that issued it: offering one connection's devices while another is selected
  // would build a forward pointing at a name the chosen network cannot resolve.
  tunnelPeers: (id: string) =>
    request<{ peers: Peer[] }>(`/api/tunnels/${encodeURIComponent(id)}/peers`).then(
      (r) => r.peers,
    ),
  updateTunnel: (id: string, patch: Record<string, unknown>) =>
    request<TunnelView>(`/api/tunnels/${encodeURIComponent(id)}`, {
      method: 'PUT',
      body: JSON.stringify(patch),
    }),
  // The spec carries only what a connection cannot be added without. Everything else is a
  // field of the connection form, written as a patch against the connection that now
  // exists, so a value is validated in one place however it was first set.
  createTunnel: (spec: TunnelSpec) =>
    request<TunnelView>('/api/tunnels', { method: 'POST', body: JSON.stringify(spec) }),
  // A connection that is up and carrying nothing is the case this exists for: nothing about
  // it has changed, so no write would rebuild it, and until now the way to fix it was
  // switching it off and on again.
  retryTunnel: (id: string) =>
    request<TunnelView>(`/api/tunnels/${encodeURIComponent(id)}/retry`, { method: 'POST' }),
  deleteTunnel: (id: string) =>
    request<void>(`/api/tunnels/${encodeURIComponent(id)}`, { method: 'DELETE' }),
  // The whole file goes to the agent rather than being read here: the format is understood in
  // exactly one place, so a directive this app cannot honour is refused by name instead of
  // being quietly dropped by a parser the settings registry does not know about.
  importTunnel: (id: string, file: string) =>
    request<TunnelView>(`/api/tunnels/${encodeURIComponent(id)}/import`, {
      method: 'POST',
      body: JSON.stringify({ file }),
    }),

  proxies: () =>
    request<{ proxies: ProxyInstanceView[] }>('/api/proxies').then((r) => r.proxies),
  // The served schema, not a bundled copy: which fields apply depends on what is switched on
  // for this installation, which this page cannot know.
  proxySchema: () => request<ProxySchemaView>('/api/proxies/schema'),
  createProxy: (spec: ProxyInstanceSpec) =>
    request<ProxyInstanceView>('/api/proxies', { method: 'POST', body: JSON.stringify(spec) }),
  updateProxy: (id: string, patch: Record<string, unknown>) =>
    request<ProxyInstanceView>(`/api/proxies/${encodeURIComponent(id)}`, {
      method: 'PUT',
      body: JSON.stringify(patch),
    }),
  // The whole ordered list, for the reason it is an array at all: the first matching rule
  // decides, so a caller sends what the list should be rather than an edit to it.
  setProxyRules: (id: string, rules: AccessRule[]) =>
    request<ProxyInstanceView>(`/api/proxies/${encodeURIComponent(id)}/rules`, {
      method: 'PUT',
      body: JSON.stringify({ rules }),
    }),
  deleteProxy: (id: string) =>
    request<void>(`/api/proxies/${encodeURIComponent(id)}`, { method: 'DELETE' }),
  // A POST because it is a question with an answer rather than a read of state, and because
  // nothing about it may be repeated by a cache or a link prefetch.
  testProxy: (id: string, address: string, protocol: AccessProtocol = 'tcp') =>
    request<ProxyTestResult>(`/api/proxies/${encodeURIComponent(id)}/test`, {
      method: 'POST',
      body: JSON.stringify({ address, protocol }),
    }),

  proxy: () => request<ProxyView>('/api/proxy'),
  traffic: () => request<TrafficView>('/api/traffic'),
  trafficBreakdown: (lane: TrafficLane) => request<TrafficBreakdown>(`/api/traffic/${lane}`),
  systemProxy: () => request<SystemProxyView>('/api/proxy/system'),
  automap: () => request<AutoMapView>('/api/automap'),
  tun: () => request<InterfaceView>('/api/tun'),
  forgetAutoMappings: () =>
    request<{ removed: number; automap: AutoMapView }>('/api/automap/forget', { method: 'POST' }),
  exitNode: () => request<ExitNodeView>('/api/exitnode'),
  // A POST because the answer is a round trip to the control plane rather than a read of
  // local state, so it must not be repeated by a cache or a link prefetch.
  suggestExitNode: () =>
    request<ExitNodeSuggestion>('/api/exitnode/suggest', { method: 'POST' }),
  routes: () => request<RoutesView>('/api/routes'),
  // A POST for the same reason: it probes every device advertising a route, which must
  // happen when someone asks rather than on every poll of this page.
  checkRoutes: () => request<RouteCheckResult>('/api/routes/check', { method: 'POST' }),
  fabric: () => request<FabricView>('/api/fabric'),
  egress: () => request<EgressView>('/api/egress'),
  // Named for the rules rather than for /api/routes, which is the tailnet's subnet routes
  // and a different thing entirely.
  routing: () => request<RoutingView>('/api/routing'),
  // The whole ordered list, for the same reason the proxy's rules are: the first matching
  // rule decides, so the order is the meaning and a caller sends what the list should be.
  setRoutingRules: (rules: RoutingRule[]) =>
    request<RoutingView>('/api/routing/rules', {
      method: 'PUT',
      body: JSON.stringify({ rules }),
    }),
  // A POST because it is a question with an answer rather than a read of state. It decides
  // the destination without dialling or resolving it.
  checkRoute: (destination: string) =>
    request<RoutingCheckResult>('/api/routing/check', {
      method: 'POST',
      body: JSON.stringify({ destination }),
    }),
  lock: () => request<LockView>('/api/lock'),
  // Its own call rather than part of the view: the key authority's history is a round
  // trip, and folding it in would run that on every poll of this page.
  lockLog: () => request<LockUpdate[]>('/api/lock/log'),
  signForLock: (nodeKey: string, rotationKey: string) =>
    request<LockView>('/api/lock/sign', {
      method: 'POST',
      body: JSON.stringify({ nodeKey, rotationKey }),
    }),
  dns: () => request<DNSView>('/api/dns'),
  // Arranging the machine raises a password prompt, so the answer is the whole view: what
  // the user wants to know afterwards is what the machine can do now.
  dnsSetup: () => request<DNSView>('/api/dns/setup', { method: 'POST' }),
  dnsProfiles: () =>
    request<{ profiles: DNSProfile[] }>('/api/dns/profiles').then((r) => r.profiles),
  createDnsProfile: (profile: Omit<DNSProfile, 'id' | 'builtIn'>) =>
    request<DNSProfile>('/api/dns/profiles', { method: 'POST', body: JSON.stringify(profile) }),
  updateDnsProfile: (id: string, profile: Omit<DNSProfile, 'id' | 'builtIn'>) =>
    request<DNSProfile>(`/api/dns/profiles/${encodeURIComponent(id)}`, {
      method: 'PUT',
      body: JSON.stringify(profile),
    }),
  deleteDnsProfile: (id: string) =>
    request<void>(`/api/dns/profiles/${encodeURIComponent(id)}`, { method: 'DELETE' }),

  dnsBlock: () => request<DNSBlockView>('/api/dns/block'),
  // Each of these answers with the whole view: what the caller wants to know after
  // downloading, pausing or resuming is what that produced, not that the write landed.
  refreshDnsBlock: () => request<DNSBlockView>('/api/dns/block/refresh', { method: 'POST' }),
  pauseDnsBlock: (minutes: number) =>
    request<DNSBlockView>('/api/dns/block/pause', {
      method: 'POST',
      body: JSON.stringify({ minutes }),
    }),
  resumeDnsBlock: () => request<DNSBlockView>('/api/dns/block/resume', { method: 'POST' }),
  applyDnsBlockPreset: (preset: string) =>
    request<DNSBlockView>('/api/dns/block/preset', {
      method: 'POST',
      body: JSON.stringify({ preset }),
    }),
  checkDnsBlock: (name: string) =>
    request<DNSBlockCheckView>(`/api/dns/block/check?name=${encodeURIComponent(name)}`),

  ips: () => request<IPSView>('/api/ips'),
  // Pausing, resuming and refreshing answer with the whole view for the same reason blocking's
  // do: what the caller wants to know is what inspection is doing now.
  refreshIps: () => request<IPSView>('/api/ips/refresh', { method: 'POST' }),
  pauseIps: (minutes: number) =>
    request<IPSView>('/api/ips/pause', { method: 'POST', body: JSON.stringify({ minutes }) }),
  resumeIps: () => request<IPSView>('/api/ips/resume', { method: 'POST' }),
  applyIpsPreset: (preset: string) =>
    request<IPSView>('/api/ips/preset', {
      method: 'POST',
      body: JSON.stringify({ preset }),
    }),
  checkIps: (dest: string) =>
    request<IPSCheckView>(`/api/ips/check?dest=${encodeURIComponent(dest)}`),
  createIpsFeed: (feed: Omit<IPSFeed, 'id' | 'builtIn'>) =>
    request<IPSFeed>('/api/ips/feeds', { method: 'POST', body: JSON.stringify(feed) }),
  updateIpsFeed: (id: string, feed: Omit<IPSFeed, 'id' | 'builtIn'>) =>
    request<IPSFeed>(`/api/ips/feeds/${encodeURIComponent(id)}`, {
      method: 'PUT',
      body: JSON.stringify(feed),
    }),
  deleteIpsFeed: (id: string) =>
    request<void>(`/api/ips/feeds/${encodeURIComponent(id)}`, { method: 'DELETE' }),
  createBlocklist: (list: Omit<Blocklist, 'id' | 'builtIn'>) =>
    request<Blocklist>('/api/dns/block/lists', { method: 'POST', body: JSON.stringify(list) }),
  updateBlocklist: (id: string, list: Omit<Blocklist, 'id' | 'builtIn'>) =>
    request<Blocklist>(`/api/dns/block/lists/${encodeURIComponent(id)}`, {
      method: 'PUT',
      body: JSON.stringify(list),
    }),
  deleteBlocklist: (id: string) =>
    request<void>(`/api/dns/block/lists/${encodeURIComponent(id)}`, { method: 'DELETE' }),

  presets: () => request<{ presets: Preset[] }>('/api/presets').then((r) => r.presets),
  createPreset: (preset: Omit<Preset, 'id' | 'builtIn'>) =>
    request<Preset>('/api/presets', { method: 'POST', body: JSON.stringify(preset) }),
  deletePreset: (id: string) =>
    request<void>(`/api/presets/${encodeURIComponent(id)}`, { method: 'DELETE' }),

  telemetry: () => request<TelemetryView>('/api/telemetry'),
  telemetryEvents: (query: TelemetryQuery = {}) =>
    request<TelemetryPage>(`/api/telemetry/events${telemetryQuery(query)}`),

  settings: () => request<Settings>('/api/settings'),
  updateSettings: (patch: SettingsPatch) =>
    request<SettingsResponse>('/api/settings', { method: 'PUT', body: JSON.stringify(patch) }),
  // The served schema resolves each field's availability against the stored config,
  // which the generated copy bundled with this page cannot know.
  settingsSchemaLive: () => request<SettingsSchemaView>('/api/settings/schema'),
  prefs: () => request<PrefsView>('/api/prefs'),

  autostart: () => request<AutostartView>('/api/autostart'),
  setAutostart: (enabled: boolean) =>
    request<AutostartView>('/api/autostart', {
      method: 'POST',
      body: JSON.stringify({ enabled }),
    }),

  policyPreview: (req: PolicyBootstrapRequest) =>
    request<PolicyPlanView>('/api/policy/preview', { method: 'POST', body: JSON.stringify(req) }),
  policyApply: (req: PolicyBootstrapRequest) =>
    request<PolicyPlanView>('/api/policy/apply', { method: 'POST', body: JSON.stringify(req) }),
}
