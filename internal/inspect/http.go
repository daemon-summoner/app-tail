// SPDX-License-Identifier: MIT

package inspect

// The head of an HTTP/1.x request, which is the plaintext twin of the TLS hello: the same
// question -- what name is this connection really for -- answered by the Host header
// instead of by the SNI, on the connections that are still not encrypted.

import "bytes"

// maxMethod is the room a method name gets. The longest one in use is seven characters, so
// anything longer is not a method and the parse says so rather than reading further.
const maxMethod = 16

// httpMethods are the words a request may start with. The list is closed on purpose: the
// first bytes of a connection are read to decide whether it is HTTP at all, and a parser
// that accepted any token would call every protocol HTTP on the strength of its first word.
var httpMethods = [...][]byte{
	[]byte("GET"), []byte("POST"), []byte("PUT"), []byte("HEAD"), []byte("DELETE"),
	[]byte("OPTIONS"), []byte("PATCH"), []byte("TRACE"), []byte("CONNECT"),
}

// httpVersions are the versions a request line may end with. HTTP/2 and HTTP/3 do not have
// a request line at all, so a head parser is the whole of what they are not.
var httpVersions = [...][]byte{[]byte("HTTP/1.1"), []byte("HTTP/1.0")}

// hostHeaderName is the one header this reads. Everything else in the head is walked past
// by the same loop, so an unknown header costs a line and nothing else.
var hostHeaderName = []byte("host")

// HTTPHead is what a request said before its body, in fixed room so reading it allocates
// nothing.
type HTTPHead struct {
	method    [maxMethod]byte
	methodLen int
	host      [maxName]byte
	hostLen   int
}

// Method is the request method, empty when the head carried none.
func (h HTTPHead) Method() string {
	if h.methodLen == 0 {
		return ""
	}
	return string(h.method[:h.methodLen])
}

// Host is the name the request is for, with any port stripped, empty when there was no Host
// header. It is the field a rule matches on, so it is a string and everything else is not.
func (h HTTPHead) Host() string {
	if h.hostLen == 0 {
		return ""
	}
	return string(h.host[:h.hostLen])
}

// ParseHTTPHead reads the request line and headers out of the window.
//
// It stops at the blank line that ends the head, so a request whose body is still arriving
// is Parsed rather than Incomplete: the body is not read here and never will be.
func ParseHTTPHead(win []byte) (HTTPHead, State) {
	var head HTTPHead
	if len(win) == 0 {
		return head, Incomplete
	}

	line, rest, ended := nextLine(win)
	if !ended {
		// The method is enough to know this is not HTTP, without waiting for the rest of a
		// line that will never make it one.
		if !methodPrefix(win) {
			return head, NotThis
		}
		return head, Incomplete
	}
	method, ok := requestMethod(line)
	if !ok {
		return head, NotThis
	}
	head.methodLen = copy(head.method[:], method)

	for {
		line, rest, ended = nextLine(rest)
		if !ended {
			return head, Incomplete
		}
		if len(line) == 0 {
			return head, Parsed
		}
		if host, ok := hostHeader(line); ok && head.hostLen == 0 {
			head.hostLen = copy(head.host[:], host)
		}
	}
}

// requestMethod reads the method off a request line, and reports whether the line is a
// request line at all: a known method, then a target, then an HTTP version.
func requestMethod(line []byte) ([]byte, bool) {
	first := bytes.IndexByte(line, ' ')
	if first <= 0 || first > maxMethod {
		return nil, false
	}
	method := line[:first]
	if !knownMethod(method) {
		return nil, false
	}
	// The version at the end is what separates a request line from a line that merely
	// starts with a word: without it, "GET well soon" reads as a request.
	rest := line[first+1:]
	space := bytes.LastIndexByte(rest, ' ')
	if space < 0 {
		return nil, false
	}
	if !knownVersion(rest[space+1:]) {
		return nil, false
	}
	return method, true
}

func knownMethod(word []byte) bool {
	for _, method := range httpMethods {
		if bytes.Equal(word, method) {
			return true
		}
	}
	return false
}

func knownVersion(word []byte) bool {
	for _, version := range httpVersions {
		if bytes.Equal(word, version) {
			return true
		}
	}
	return false
}

// methodPrefix reports the bytes so far being the start of a method, which is how a request
// line that has not finished arriving is told from bytes that are not HTTP at all.
func methodPrefix(win []byte) bool {
	if len(win) > maxMethod {
		win = win[:maxMethod]
	}
	if cut := bytes.IndexByte(win, ' '); cut >= 0 {
		return knownMethod(win[:cut])
	}
	for _, method := range httpMethods {
		if bytes.HasPrefix(method, win) {
			return true
		}
	}
	return false
}

// hostHeader reads the Host header off a header line, with any port stripped: a rule names
// a host, and a value that kept the port would never match one.
func hostHeader(line []byte) ([]byte, bool) {
	colon := bytes.IndexByte(line, ':')
	if colon <= 0 {
		return nil, false
	}
	if !bytes.EqualFold(line[:colon], hostHeaderName) {
		return nil, false
	}
	value := bytes.TrimSpace(line[colon+1:])
	if len(value) == 0 || len(value) > maxName {
		return nil, false
	}
	// A bracketed address is an IPv6 literal, where the colons are part of the address
	// rather than a port separator.
	if value[0] == '[' {
		end := bytes.IndexByte(value, ']')
		if end <= 0 || !printableName(value[:end+1]) {
			return nil, false
		}
		return value[:end+1], true
	}
	if cut := bytes.IndexByte(value, ':'); cut >= 0 {
		value = value[:cut]
	}
	// A host carrying a control character is dropped rather than trimmed, for the reason the
	// server name is: this value reaches a log line and an event field, and a name is not a
	// place to carry a carriage return.
	if !printableName(value) {
		return nil, false
	}
	return value, true
}

// nextLine cuts one CRLF-terminated line, reporting whether one was there. A bare LF ends a
// line too: clients send them, and a parser that insisted on the pair would read a whole
// request as one unterminated line.
func nextLine(win []byte) (line, rest []byte, ended bool) {
	at := bytes.IndexByte(win, '\n')
	if at < 0 {
		return win, nil, false
	}
	line = win[:at]
	if len(line) > 0 && line[len(line)-1] == '\r' {
		line = line[:len(line)-1]
	}
	return line, win[at+1:], true
}
