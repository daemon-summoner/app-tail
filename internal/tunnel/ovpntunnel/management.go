// SPDX-License-Identifier: MIT

package ovpntunnel

// OpenVPN's management interface, which is the whole of how this app drives a connection it
// does not run itself.
//
// The direction is worth being clear about, because it is what makes the arrangement safe.
// openvpn -- started with administrator rights by the privileged helper -- creates the socket
// in a directory belonging to root, at a path the helper chooses from the connection id, and
// this side dials it. openvpn is told the one account allowed to connect (openvpn(8):
// "--management-client-user u: When the management interface is listening on a unix domain
// socket, only allow connections from user u"), so no other account on the machine can drive
// a root process through it, and nothing this side names decides where root creates a file or
// what it connects to. When the conversation drops, openvpn restarts and holds until it is
// driven again (--management-signal), so a connection never carries on with nothing watching
// it; the helper stops it outright when its session ends.
//
// Credentials travel here rather than in the configuration file. The file is written by a
// root process into a directory this app cannot read; answering the account prompt over this
// socket instead means the password never lands on disk at all.

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sellitus/app-tail/internal/hostnet"
)

// bytecountSeconds is how often openvpn is asked to report what it has carried. It is a
// counter read for the traffic graph rather than anything a decision is made on, so it is
// slow enough to cost nothing and fast enough that a graph drawn every few seconds moves.
const bytecountSeconds = 5

// maxManagementLine bounds one line off the socket. openvpn's own log lines are the longest
// thing that arrives here and they are well under this; the bound exists because this is a
// stream from another process, and a reader with no limit is memory that process decides the
// size of.
const maxManagementLine = 64 << 10

// report is what openvpn last said about the connection, as one state notification.
//
// The field list is openvpn's own, in its own order: time, state name, description, the
// interface's IPv4 address, the server's address and port, this machine's local address and
// port, and the interface's IPv6 address.
type report struct {
	// Name is one of openvpn's state names: CONNECTING, WAIT, AUTH, GET_CONFIG, ASSIGN_IP,
	// ADD_ROUTES, CONNECTED, RECONNECTING, EXITING, RESOLVE, TCP_CONNECT, AUTH_PENDING.
	Name string
	// Detail is the description openvpn attaches, which carries the reason on RECONNECTING
	// and EXITING and is the only place that reason appears.
	Detail string
	// TunV4 and TunV6 are the addresses this device holds inside the network. They come from
	// the server, which is the one thing about this connection only the server knows.
	TunV4, TunV6 netip.Addr
	// Server is the address this connection's own packets are being sent to, which is what
	// has to keep leaving through this machine's own network.
	Server netip.Addr
}

// Connected reports the one state in which traffic crosses.
func (r report) Connected() bool { return r.Name == "CONNECTED" }

// parseState reads one >STATE: notification. It is pure, so every arm -- including the
// states that only happen on a server that is refusing, which no test can produce -- is
// reachable without a connection.
func parseState(line string) (report, bool) {
	rest, ok := strings.CutPrefix(line, ">STATE:")
	if !ok {
		return report{}, false
	}
	fields := strings.Split(rest, ",")
	if len(fields) < 2 || fields[1] == "" {
		return report{}, false
	}
	out := report{Name: fields[1]}
	if len(fields) > 2 {
		out.Detail = fields[2]
	}
	out.TunV4 = addrAt(fields, 3)
	out.Server = addrAt(fields, 4)
	out.TunV6 = addrAt(fields, 8)
	return out, true
}

// addrAt reads one address out of a notification, leaving it invalid when the field is
// absent or is not an address. openvpn leaves most of them empty in most states, so an
// unparseable field is the ordinary case rather than a fault.
func addrAt(fields []string, i int) netip.Addr {
	if i >= len(fields) {
		return netip.Addr{}
	}
	addr, err := netip.ParseAddr(strings.TrimSpace(fields[i]))
	if err != nil {
		return netip.Addr{}
	}
	return addr.Unmap()
}

// parseBytecount reads one >BYTECOUNT: notification: what has come in and gone out since the
// connection started, as cumulative totals.
func parseBytecount(line string) (in, out int64, ok bool) {
	rest, found := strings.CutPrefix(line, ">BYTECOUNT:")
	if !found {
		return 0, 0, false
	}
	inText, outText, split := strings.Cut(rest, ",")
	if !split {
		return 0, 0, false
	}
	in, err := strconv.ParseInt(strings.TrimSpace(inText), 10, 64)
	if err != nil {
		return 0, 0, false
	}
	out, err = strconv.ParseInt(strings.TrimSpace(outText), 10, 64)
	if err != nil {
		return 0, 0, false
	}
	return in, out, true
}

// parseLog reads one >LOG: notification into the message itself. The line carries a time and
// a set of one-letter flags in front of the text, and the text may contain commas, so it is
// split a fixed number of times rather than on every separator.
func parseLog(line string) (text string, ok bool) {
	rest, found := strings.CutPrefix(line, ">LOG:")
	if !found {
		return "", false
	}
	fields := strings.SplitN(rest, ",", 3)
	if len(fields) < 3 {
		return "", false
	}
	return fields[2], true
}

// parsePushReply reads the options a server offered out of a log line.
//
// What this connection carries and what this machine does with its own traffic stay what
// app-tail was told rather than what the server asked for, so the routes here are read and not
// acted on: a route the server expected to install is the single most likely reason a
// destination that ought to work does not, and a user who can see the list can add it in one
// place. The resolvers are the exception, and only when nothing is configured here -- see
// servedResolvers.
func parsePushReply(text string) ([]string, bool) {
	start := strings.Index(text, "PUSH_REPLY,")
	if start < 0 {
		return nil, false
	}
	rest := text[start+len("PUSH_REPLY,"):]
	// The message arrives quoted in openvpn's log line, so anything past the closing quote
	// belongs to the log rather than to the reply.
	if end := strings.IndexByte(rest, '\''); end >= 0 {
		rest = rest[:end]
	}
	var out []string
	for _, option := range strings.Split(rest, ",") {
		option = strings.TrimSpace(option)
		switch {
		case option == "":
		case strings.HasPrefix(option, "route "),
			strings.HasPrefix(option, "route-ipv6 "),
			strings.HasPrefix(option, "dhcp-option "),
			strings.HasPrefix(option, "redirect-gateway"):
			out = append(out, option)
		}
	}
	return out, len(out) > 0
}

// servedResolvers are the name servers a server handed this connection, read off the options
// it pushed.
//
// A network's own resolvers are the only thing that knows the names inside it, and a server
// that hands them out is answering a question nothing else can. They are used only when no
// resolver is configured for the connection: a configured one is the user's answer and is not
// overridden, and the alternative to using these is a name inside the network that resolves
// nowhere at all.
//
// Nothing else the server pushes is acted on, and these are held for as long as the connection
// runs rather than written into what is stored.
func servedResolvers(pushed []string) []netip.Addr {
	var out []netip.Addr
	for _, option := range pushed {
		fields := strings.Fields(option)
		if len(fields) != 3 || fields[0] != "dhcp-option" {
			continue
		}
		if kind := strings.ToUpper(fields[1]); kind != "DNS" && kind != "DNS6" {
			continue
		}
		addr, err := netip.ParseAddr(fields[2])
		if err != nil {
			// A resolver that is not an address is one nothing can be asked at. openvpn also
			// pushes DOMAIN and the other dhcp-option kinds through here, so this is ordinary
			// rather than a fault, and the whole list stays on the connection either way.
			continue
		}
		out = append(out, addr.Unmap())
	}
	return out
}

// maxNoticeLen bounds one notice taken off the log. openvpn's own lines are short; the bound
// is there because this text is put on the connection and read on a dashboard, where a line
// another program decides the length of is a line that breaks the page.
const maxNoticeLen = 200

// openvpnNotices are the fragments of an openvpn log line that say why a connection is not
// coming up.
//
// openvpn reports these on its log rather than as a state: a handshake that never completes,
// an account the server refused, a certificate whose name does not match all leave the state
// at connecting and say what happened only here. They are matched on openvpn's own wording
// because that wording is what it writes; the line is then carried through as it stands
// rather than translated, so what is on screen is what openvpn said.
var openvpnNotices = []string{
	"AUTH_FAILED",
	"TLS Error",
	"VERIFY ERROR",
	"VERIFY X509NAME ERROR",
	"certificate verify failed",
	"Connection reset",
	"Connection refused",
	"Server poll timeout",
	"Cannot resolve host address",
	"No route to host",
	"Network is unreachable",
	"private key password verification failed",
	"Options error",
}

// noticeFrom picks the reason out of one log line, or reports that the line carries none.
func noticeFrom(text string) (string, bool) {
	notice := strings.TrimSpace(text)
	if notice == "" {
		return "", false
	}
	found := false
	for _, marker := range openvpnNotices {
		if strings.Contains(notice, marker) {
			found = true
			break
		}
	}
	if !found {
		return "", false
	}
	if len(notice) > maxNoticeLen {
		// ToValidUTF8 because the cut may land inside a character, and a broken one would
		// travel from here to a dashboard.
		notice = strings.ToValidUTF8(notice[:maxNoticeLen], "") + "..."
	}
	return notice, true
}

// deadEndpointMarkers are the reasons that condemn the address being dialled rather than the
// material being dialled with: nothing answered, something refused, or the thing that answered
// was not an OpenVPN server. No key and no digest changes any of that, so an attempt that ends
// this way takes every other attempt at the same address down with it.
var deadEndpointMarkers = []string{
	// openvpn's wording when the peer talks something other than the OpenVPN protocol, which
	// is what a name server or a web server on the configured port looks like from here.
	"client->client or server->server connection attempted",
	"Connection refused",
	"No route to host",
	"Network is unreachable",
}

// unreachedMarkers are the reasons a handshake never completed. Unlike a refused account or a
// certificate whose name does not match, they do not say the server was reached and said no:
// a control channel signed the way this server does not expect is dropped in silence, and it
// looks exactly like this.
var unreachedMarkers = []string{
	"TLS Error",
	"Connection reset",
	"Server poll timeout",
}

// reachFailure reports whether a notice says this connection never got to a server, and
// whether the address it was dialling is the part that is wrong.
func reachFailure(notice string) (deadEndpoint, unreached bool) {
	for _, marker := range deadEndpointMarkers {
		if strings.Contains(notice, marker) {
			return true, true
		}
	}
	for _, marker := range unreachedMarkers {
		if strings.Contains(notice, marker) {
			return false, true
		}
	}
	return false, false
}

// credentials are what the server may ask this connection for. They are answered over this
// socket and never written to the configuration file.
type credentials struct {
	Username      string
	Password      string
	KeyPassphrase string
}

// replies are the lines that answer one >PASSWORD: prompt.
//
// A prompt with no answer configured is an error rather than silence. openvpn waits
// indefinitely for an answer it was told to ask the management interface for, so a
// connection that stayed quiet here would sit in AUTH forever with nothing saying why.
func (c credentials) replies(prompt string) ([]string, error) {
	if failed, ok := strings.CutPrefix(prompt, "Verification Failed: "); ok {
		return nil, fmt.Errorf("the server refused this connection's credentials for %s",
			strings.Trim(failed, "'"))
	}
	rest, ok := strings.CutPrefix(prompt, "Need '")
	if !ok {
		return nil, fmt.Errorf("the connection asked for something this app does not know how to answer: %s", prompt)
	}
	name, want, ok := strings.Cut(rest, "' ")
	if !ok {
		return nil, fmt.Errorf("the connection asked for something this app does not know how to answer: %s", prompt)
	}

	switch want {
	case "password":
		if name == "Private Key" {
			if c.KeyPassphrase == "" {
				return nil, errors.New("this connection's private key is encrypted and no passphrase is stored for it")
			}
			return []string{"password " + quoteManagement(name) + " " + quoteManagement(c.KeyPassphrase)}, nil
		}
		if c.Password == "" {
			return nil, fmt.Errorf("the server asked for a %s password and none is stored for this connection", name)
		}
		return []string{"password " + quoteManagement(name) + " " + quoteManagement(c.Password)}, nil

	case "username":
		if c.Username == "" {
			return nil, fmt.Errorf("the server asked for a %s username and none is stored for this connection", name)
		}
		return []string{"username " + quoteManagement(name) + " " + quoteManagement(c.Username)}, nil

	case "username/password":
		if c.Username == "" || c.Password == "" {
			return nil, fmt.Errorf("the server asked for a %s username and password, and this connection has "+
				"no account stored", name)
		}
		return []string{
			"username " + quoteManagement(name) + " " + quoteManagement(c.Username),
			"password " + quoteManagement(name) + " " + quoteManagement(c.Password),
		}, nil
	}
	return nil, fmt.Errorf("the connection asked for a %s this app does not know how to answer", want)
}

// quoteManagement renders one argument the way the management interface reads it: quoted,
// with a quotation mark or a backslash inside escaped by a backslash.
//
// Everything is quoted rather than only the values that need it. A password with a space in
// it would otherwise be read as two arguments, and the failure that produces is a login that
// is refused for a reason nobody can see.
func quoteManagement(s string) string {
	var b strings.Builder
	b.Grow(len(s) + 2)
	b.WriteByte('"')
	for _, r := range s {
		if r == '"' || r == '\\' {
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	b.WriteByte('"')
	return b.String()
}

// managementDialTimeout bounds how long a program that has just been started is given to
// open its management socket. openvpn does that before anything that waits on the network,
// within milliseconds of starting, so this is generous: what it guards against is a program
// that died at once, or one that came up with no management interface at all.
const managementDialTimeout = 10 * time.Second

// managementDialEvery is how often the socket is tried while it is not there yet.
const managementDialEvery = 50 * time.Millisecond

// dialManagement connects to the management socket of a program that has just been started,
// trying again until it answers or the time runs out.
//
// The socket not being there yet and nothing listening on it yet are both what a program a
// few milliseconds old looks like, so either is tried again; the last thing that went wrong is
// what a timeout reports.
func dialManagement(ctx context.Context, path string) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, managementDialTimeout)
	defer cancel()
	var dialer net.Dialer
	tick := time.NewTicker(managementDialEvery)
	defer tick.Stop()
	for {
		conn, err := dialer.DialContext(ctx, "unix", path)
		if err == nil {
			return conn, nil
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("reach this connection's management socket %s: %w (last attempt: %v)", path, ctx.Err(), err)
		case <-tick.C:
		}
	}
}

// link is one management conversation: the socket, what it heard, and the one way to speak
// back down it.
type link struct {
	creds credentials

	// The four things this conversation reports. Each is called from the reading goroutine,
	// so none of them may block on anything that goroutine has to do next.
	onReport func(report)
	onBytes  func(in, out int64)
	onPushed func([]string)
	onLog    func(text string)
	// onDevice carries the interface openvpn opened. Nothing else on this machine knows
	// which one it is: the kernel picks it, and two connections to the same provider hold
	// the same address on it, so the address cannot be used to tell them apart.
	onDevice func(name string)
	// onNotice carries the reason a connection is not coming up, which openvpn says on its
	// log rather than in the state it reports.
	onNotice func(text string)
	// onProblem carries a failure the connection cannot recover from on its own: credentials
	// the server refused, a prompt with no stored answer, a fatal error from openvpn.
	onProblem func(err error)

	mu   sync.Mutex
	conn net.Conn
}

// handle runs one conversation, until the program at the other end goes or the context ends.
//
// A link outlives any one program: a restart onto the next way of reaching the server starts a
// new program and dials it while the old conversation is still winding down. So the old one
// only lets go of the socket it held itself, and never of the one that replaced it.
func (l *link) handle(ctx context.Context, conn net.Conn) {
	l.mu.Lock()
	l.conn = conn
	l.mu.Unlock()
	defer func() {
		l.mu.Lock()
		if l.conn == conn {
			l.conn = nil
		}
		l.mu.Unlock()
		if err := conn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			l.onProblem(fmt.Errorf("close this connection's management socket: %w", err))
		}
	}()

	// Notifications first and the hold released only in response to openvpn's own >HOLD:,
	// so nothing about the connection happens before there is something here to hear it.
	for _, command := range []string{
		"state on",
		"log on",
		"bytecount " + strconv.Itoa(bytecountSeconds),
	} {
		if err := l.send(command); err != nil {
			l.onProblem(err)
			return
		}
	}

	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, 0, 4096), maxManagementLine)
	for scanner.Scan() {
		l.dispatch(strings.TrimRight(scanner.Text(), "\r"))
	}
	if err := scanner.Err(); err != nil && ctx.Err() == nil && !errors.Is(err, net.ErrClosed) &&
		!errors.Is(err, io.EOF) {
		l.onProblem(fmt.Errorf("read from this connection's management socket: %w", err))
	}
}

// dispatch acts on one line from openvpn.
func (l *link) dispatch(line string) {
	switch {
	case strings.HasPrefix(line, ">STATE:"):
		if state, ok := parseState(line); ok {
			l.onReport(state)
		}

	case strings.HasPrefix(line, ">BYTECOUNT:"):
		if in, out, ok := parseBytecount(line); ok {
			l.onBytes(in, out)
		}

	case strings.HasPrefix(line, ">LOG:"):
		text, ok := parseLog(line)
		if !ok {
			return
		}
		l.onLog(text)
		if device, found := hostnet.OpenVPNDeviceOpened(text); found {
			l.onDevice(device)
		}
		if notice, found := noticeFrom(text); found {
			l.onNotice(notice)
		}
		if pushed, found := parsePushReply(text); found {
			l.onPushed(pushed)
		}

	case strings.HasPrefix(line, ">PASSWORD:"):
		replies, err := l.creds.replies(strings.TrimPrefix(line, ">PASSWORD:"))
		if err != nil {
			l.onProblem(err)
			return
		}
		for _, reply := range replies {
			if err := l.send(reply); err != nil {
				l.onProblem(err)
				return
			}
		}

	case strings.HasPrefix(line, ">HOLD:"):
		// openvpn was started held, so that it does not reach the server before there is
		// anything here listening to what it reports. This is the release.
		if err := l.send("hold release"); err != nil {
			l.onProblem(err)
		}

	case strings.HasPrefix(line, ">FATAL:"):
		l.onProblem(errors.New(strings.TrimPrefix(line, ">FATAL:")))

	case strings.HasPrefix(line, "ERROR:"):
		l.onProblem(errors.New(strings.TrimPrefix(line, "ERROR:")))
	}
}

// close ends the conversation now running, if there is one. It is how a connection being
// taken down lets go of the socket once the program has been asked to stop.
func (l *link) close() {
	l.mu.Lock()
	conn := l.conn
	l.conn = nil
	l.mu.Unlock()
	if conn == nil {
		return
	}
	if err := conn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		l.onProblem(fmt.Errorf("close this connection's management socket: %w", err))
	}
}

// send writes one command, or reports that there is nothing to write to. A caller that
// reaches this after openvpn has gone is answered rather than left waiting.
func (l *link) send(command string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.conn == nil {
		return errors.New("this connection is not reachable: nothing is on its management socket")
	}
	if _, err := io.WriteString(l.conn, command+"\n"); err != nil {
		return fmt.Errorf("send a command to this connection: %w", err)
	}
	return nil
}
