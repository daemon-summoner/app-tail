// SPDX-License-Identifier: MIT

package fabric

// Every private network this app holds, on one interface on this machine.
//
// The other two ways app-tail offers a network -- a forwarded port, a proxy a program is
// pointed at -- reach one destination each and need the program to be told about them. This
// reaches all of them, by address, with no per-program setup: the machine's routing table
// sends a whole range at this interface, and everything arriving on it is terminated here
// and re-dialled inside the network the address belonged to.
//
// It is the only mode that can present a network somewhere other than its own addresses,
// which is what makes two networks that both use 10.0.0.0/8 usable at the same time.
//
// What it costs, stated here rather than found later:
//
//   - Only TCP and UDP cross. ESP, GRE and SCTP do not, and neither does ICMP -- a ping to
//     an address on one of these networks goes unanswered. Answering it from this side
//     would report a round trip to this machine's own process as if it were the round trip
//     to the host, which is a lie told to the one tool people reach for to find out whether
//     a host is there.
//   - Every destination is one hop away. There is no path to trace, because no packet from
//     this machine ever travels to it.
//   - Datagrams are not re-segmented the way a byte stream is, so the interface's MTU is the
//     smallest of the connected networks' -- see MTU.
//   - Every byte is copied through this process, so a single transfer runs at a fraction of
//     what a kernel interface does.
//
// The one thing it is better at: each side negotiates its segment size against its own MTU,
// so a path through two of these does not have to satisfy both at once.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"

	"github.com/tailscale/wireguard-go/tun"

	"github.com/sellitus/app-tail/internal/bytecount"
)

// Limits are what this mode cannot carry, in the words the dashboard shows. They are
// stated rather than discovered because every one of them is otherwise reported as a bug
// against an interface working exactly as it can.
var Limits = []string{
	"Only TCP and UDP reach these networks. A ping goes unanswered, a traceroute shows " +
		"one hop, and protocols like ESP, GRE and SCTP do not cross at all.",
	"Every byte passes through app-tail, so a single transfer is slower than it would be " +
		"over a connection this machine holds itself.",
	"The interface carries packets no larger than the smallest connected network's, " +
		"because a datagram cannot be split the way a byte stream can.",
}

// Options are what a fabric is built from.
type Options struct {
	// Device is the interface on this machine. The fabric closes it: the read it spends
	// its life blocked in ends no other way.
	Device tun.Device
	// Carriers is where the connection an address belongs to is looked up.
	Carriers Carriers
	// MTU is the largest packet the interface carries. It must be the smallest of the
	// connected networks' own, or a datagram this machine sends will be too big for the
	// network it ends up on and will be dropped with nothing reporting why.
	MTU int
	// Table is the addressing to start with. It is replaced whenever the connections
	// change; a fabric with no table carries nothing and says so.
	Table *Table
	// Names is what each connection is called, for the sentences a refusal carries. A
	// connection missing from it is named by its id.
	Names map[string]string
	// SessionBudget is how many flows one connection may hold at once. Zero takes the
	// default.
	SessionBudget int
	// Seed is what a flow's destination is hashed with when several connections carry one
	// range together. It belongs to this machine and is persisted, so a site keeps the
	// connection it left through across a restart rather than being reshuffled.
	Seed   uint64
	Logger *slog.Logger
}

// Fabric is one host interface carrying every connected network.
type Fabric struct {
	dev      tun.Device
	stack    *netStack
	carriers Carriers
	sessions *sessions
	open     *openFlows
	logger   *slog.Logger
	mtu      int
	seed     uint64

	// inspector examines every flow before it is carried. It is atomic rather than under
	// f.mu because it is read once per flow on the path that opens them, and putting that
	// read behind the lock that also guards the addressing would queue every new connection
	// on this machine behind whatever is reading the table.
	inspector atomic.Pointer[Inspector]

	ctx    context.Context
	cancel context.CancelFunc

	mu    sync.RWMutex
	table *Table
	names map[string]string
	// tally is per connection because that is how it is read: a connection carrying
	// nothing while another carries everything is the answer to "why is this one slow",
	// and one machine-wide total cannot give it.
	//
	// It is on a lock of its own, held only to find or make an entry -- once per flow, never
	// per chunk. Counting under f.mu would put every transfer on this machine in line behind
	// the one lock that also guards the addressing and answers every dashboard poll.
	tallyMu sync.Mutex
	tally   map[string]*tally
	// ports breaks the same bytes down by the port and transport a flow used, which is the
	// finest cut anything in app-tail can make: the interface is the one place where every
	// flow this machine sends is seen with its full address before it leaves. It is bounded
	// on its own because the set is whatever programs on this machine open.
	ports  *bytecount.Table
	closed bool
}

// maxPorts is how many port-and-transport pairs the interface names before folding the rest
// into one bucket. It is the budget the proxy's destination table keeps, for the same reason.
const maxPorts = 64

// tally is one connection's running totals. The fields are added to from every flow that
// connection carries at once, so they are atomic rather than guarded: the alternative is a
// lock taken on both sides of every 32 KB chunk that crosses.
type tally struct {
	flows    atomic.Uint64
	refused  atomic.Uint64
	sent     atomic.Uint64
	received atomic.Uint64
}

// read is the tally as the dashboard sees it. The four loads are not one instant -- a
// transfer in flight can land between them -- which is the same looseness the counters
// already had, and finer would mean a lock back on the counting path to answer a poll.
func (t *tally) read() Counters {
	return Counters{
		Flows:    t.flows.Load(),
		Refused:  t.refused.Load(),
		Sent:     t.sent.Load(),
		Received: t.received.Load(),
	}
}

// Counters are what one connection carried.
type Counters struct {
	// Flows is how many connections and datagram flows were handed on, Refused how many
	// were turned away. A refusal is counted against the connection that would have
	// carried it, and against no connection at all when the address belonged to none.
	Flows   uint64
	Refused uint64
	// Sent is what this machine put into the network, Received what came back.
	Sent     uint64
	Received uint64
	// Holding is how many flows are open right now.
	Holding int
}

// Status is what the fabric is doing.
type Status struct {
	// Interface is the name the operating system gave it, empty when it is not up.
	Interface string
	// Running reports that the interface is carrying traffic.
	Running bool
	// MTU is the largest packet it carries.
	MTU int
	// Routes are the ranges the machine sends to this interface.
	Routes []netip.Prefix
	// Networks is the addressing: which connection is reached where.
	Networks []Mapping
	// Counters are per connection, keyed by connection id. The empty key is what was
	// refused because no connection carried the address at all.
	Counters map[string]Counters
	// Error is why it stopped, kept because an interface that is up and carrying nothing
	// is otherwise indistinguishable from one with nothing to carry.
	Error string
}

// New builds the fabric and starts carrying traffic.
//
// It carries traffic from the moment it returns. There is no separate start step, because
// the machine's routes are pointed at this interface by the caller and every moment between
// the two is one where programs on this machine reach a private network's addresses and get
// nothing back.
func New(opts Options) (*Fabric, error) {
	if opts.Carriers == nil {
		return nil, errors.New("the fabric was given nothing to re-dial connections through")
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	ctx, cancel := context.WithCancel(context.Background())
	f := &Fabric{
		dev:      opts.Device,
		carriers: opts.Carriers,
		sessions: newSessions(opts.SessionBudget),
		open:     newOpenFlows(),
		logger:   logger,
		mtu:      opts.MTU,
		seed:     opts.Seed,
		ctx:      ctx,
		cancel:   cancel,
		table:    opts.Table,
		names:    copyNames(opts.Names),
		tally:    make(map[string]*tally),
		ports:    bytecount.New(maxPorts),
	}

	s, err := newStack(opts.Device, opts.MTU, logger, f.handleTCP, f.handleUDP)
	if err != nil {
		cancel()
		return nil, err
	}
	f.stack = s
	return f, nil
}

// SetTable replaces the addressing.
//
// A flow already being carried keeps the answer it was given for as long as that answer
// still stands: a connection that is open is a connection to a host on one network, and
// moving it to whatever now holds those addresses would send the rest of its bytes somewhere
// else entirely.
//
// A flow the new addressing answers differently is ended instead of left running. That is
// the switch a person asks for: the network moved to another connection, or the connection
// carrying this machine's internet traffic changed, and traffic still leaving through the
// connection they took away is the switch not having happened. The program dials again and
// is answered by the addressing now in force.
func (f *Fabric) SetTable(t *Table, names map[string]string) {
	f.mu.Lock()
	f.table = t
	f.names = copyNames(names)
	f.mu.Unlock()

	// Outside the lock: ending a flow closes both of its connections, and the goroutines
	// that unwind count what they carried against this same lock.
	if ended := f.open.endWhatMoved(t); ended > 0 {
		f.logger.Info("ended carried flows whose network is no longer reached the same way",
			"flows", ended)
	}
}

// Table is the addressing in force right now.
func (f *Fabric) Table() *Table {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.table
}

// MTU is the largest packet this interface carries.
func (f *Fabric) MTU() int { return f.mtu }

// Done is closed once the fabric has stopped carrying traffic, whether it was closed or the
// interface went away underneath it.
func (f *Fabric) Done() <-chan struct{} { return f.stack.Done() }

// Status is what the fabric is doing. It reads cached state only: it is called on every
// dashboard poll.
func (f *Fabric) Status(name string) Status {
	f.mu.RLock()
	table := f.table
	f.mu.RUnlock()

	held := f.sessions.counts()
	status := Status{
		Interface: name,
		Running:   f.stack.Err() == nil && f.ctx.Err() == nil,
		MTU:       f.mtu,
		Routes:    table.Routes(),
		Networks:  table.Mappings(),
		Counters:  make(map[string]Counters),
	}
	if err := f.stack.Err(); err != nil {
		status.Error = err.Error()
	}

	f.tallyMu.Lock()
	for id, counted := range f.tally {
		entry := counted.read()
		entry.Holding = held[id]
		status.Counters[id] = entry
	}
	f.tallyMu.Unlock()
	// A connection carrying flows this instant but none since the counters were last
	// touched still belongs in the answer.
	for id, n := range held {
		if _, seen := status.Counters[id]; !seen {
			status.Counters[id] = Counters{Holding: n}
		}
	}
	return status
}

// Close stops carrying traffic and releases the interface.
//
// The order is the whole of it: the pumps are told to stop, then the interface is closed --
// which is what unblocks the read one of them is sitting in -- and only once both have
// returned is the stack torn down. Tearing it down first would pull the endpoints out from
// under a pump still writing to them.
func (f *Fabric) Close() error {
	f.mu.Lock()
	if f.closed {
		f.mu.Unlock()
		return nil
	}
	f.closed = true
	f.mu.Unlock()

	f.cancel()
	f.stack.stop()
	var failed error
	if f.dev != nil {
		if err := f.dev.Close(); err != nil && !closedAlready(err) {
			failed = fmt.Errorf("close the network interface: %w", err)
		}
	}
	f.stack.wait()
	f.stack.release()
	return failed
}

// nameOf is what a connection is called in a sentence, falling back to its id so a refusal
// never refers to a connection by nothing.
func (f *Fabric) nameOf(id string) string {
	f.mu.RLock()
	defer f.mu.RUnlock()
	if name := f.names[id]; name != "" {
		return name
	}
	return id
}

// refuse records and reports a flow that could not be carried.
//
// Every one of these is a program on this machine failing to reach something, so the reason
// is kept where a person can read it rather than only counted: the symptom otherwise is a
// connection that times out with nothing anywhere naming the network it was meant for.
// The destination it was for is passed in rather than looked up again: with several
// connections carrying one range, looking it up here without the flow's own key would count
// the refusal against whichever of them an unkeyed lookup lands on. A zero destination is an
// address no connection carried, which is counted against no connection.
func (f *Fabric) refuse(on Destination, from, at netip.AddrPort, proto string, why error) {
	f.counters(on.TunnelID).refused.Add(1)
	f.logger.Warn("refused a connection to a private network",
		"protocol", proto, "from", from.String(), "to", at.String(), "reason", why)
}

// flow is what one carried flow counts against: its connection's totals and its port's.
//
// Both entries are found once, when the flow opens, and the reporting functions only add to
// them. The lookups take locks; what they return is called on every chunk that crosses.
type flow struct {
	table *bytecount.Table
	tally *tally
	port  *bytecount.Entry
}

// begin registers one flow and returns what counts its bytes. The caller must call done
// when the flow ends, or the port it used can never be evicted to make room for another.
func (f *Fabric) begin(id string, port uint16, proto string) *flow {
	name := strconv.Itoa(int(port))
	entry := f.ports.Entry(proto+"/"+name, bytecount.Meta{
		Label:  name,
		Detail: proto,
		// The connection carrying it, so the dashboard can ask what one connection's ports
		// are doing. There is no device to name: the interface carries this machine's own
		// outbound traffic, not another device's.
		Via: id,
	})
	entry.Open()
	f.ports.Touch(entry)

	held := f.counters(id)
	held.flows.Add(1)
	return &flow{table: f.ports, tally: held, port: entry}
}

// up counts what this machine sent into a network, and down what came back.
func (l *flow) up(n int64) {
	l.tally.sent.Add(uint64(n))
	l.port.Up(n)
}

func (l *flow) down(n int64) {
	l.tally.received.Add(uint64(n))
	l.port.Down(n)
}

// done releases the port's slot for eviction and dates it, so a port nothing has used for a
// while is the one dropped when a new one needs naming.
func (l *flow) done() {
	l.port.Close()
	l.table.Touch(l.port)
}

// Ports is what each port and transport the interface carried has moved, busiest first, plus
// what the cap left unnamed and how many distinct ports that stands for.
func (f *Fabric) Ports() (named []bytecount.Row, other bytecount.Row, folded int) {
	return f.ports.Snapshot()
}

// counters is a connection's totals, made on the first thing that connection does.
func (f *Fabric) counters(id string) *tally {
	f.tallyMu.Lock()
	defer f.tallyMu.Unlock()
	held, ok := f.tally[id]
	if !ok {
		held = &tally{}
		f.tally[id] = held
	}
	return held
}

// copyNames copies a name map so a caller changing theirs afterwards cannot change what a
// refusal says halfway through.
func copyNames(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
