// SPDX-License-Identifier: MIT

package httpapi

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"strings"

	"github.com/sellitus/app-tail/internal/config"
	"github.com/sellitus/app-tail/internal/tsnode"
)

// errorBody is the response shape for every non-2xx JSON reply.
type errorBody struct {
	Error string `json:"error"`
	// Field names the rejected input. The message already begins with it, but a
	// settings form has to put the complaint on the control that caused it, and
	// splitting the sentence back apart in the client would make the wording of an
	// error message part of the API contract.
	Field string `json:"field,omitempty"`
	// Conflict names the forward already holding the endpoint, so the dashboard can
	// point at it instead of just saying "port in use".
	Conflict *conflictBody `json:"conflict,omitempty"`
	// Ref ties a failure the agent did not anticipate to the log line carrying the whole
	// of it. It is set on 5xx only: everything below that is a sentence the caller can
	// act on without anybody reading a log.
	Ref string `json:"ref,omitempty"`
}

type conflictBody struct {
	Endpoint  string `json:"endpoint"`
	ForwardID string `json:"forwardId"`
	Name      string `json:"name,omitempty"`
}

// unavailableError marks a capability the running configuration does not provide,
// such as autostart on an unsupported platform. It maps to 503.
type unavailableError struct {
	what   string
	reason string
}

func (e *unavailableError) Error() string {
	if e.reason == "" {
		return fmt.Sprintf("%s is not available", e.what)
	}
	return fmt.Sprintf("%s is not available: %s", e.what, e.reason)
}

// Unavailable builds the error returned when a dependency is absent.
func Unavailable(what, reason string) error { return &unavailableError{what: what, reason: reason} }

// ErrApprovalDeclined is an administrator's prompt that was dismissed. It maps to 409: an
// answer the person gave, not a fault, and one they can change by asking again.
var ErrApprovalDeclined = errors.New("the administrator prompt was dismissed, so nothing was approved")

// approvalByHandError is a machine where app-tail cannot raise the administrator prompt
// itself. It maps to 501, with the command to run instead in the message.
type approvalByHandError struct{ err error }

func (e *approvalByHandError) Error() string { return e.err.Error() }
func (e *approvalByHandError) Unwrap() error { return e.err }

// ApprovalByHand marks err, which names the command an administrator runs, as the answer of a
// machine where app-tail cannot ask for the approval itself.
func ApprovalByHand(err error) error { return &approvalByHandError{err: err} }

// badRequest builds a 400-mapped error for malformed input that never reaches the
// config validator (bad JSON, missing path segment, unparsable query).
func badRequest(format string, args ...any) error {
	return &config.ValidationError{Field: "request", Message: fmt.Sprintf(format, args...)}
}

// writeJSON emits a JSON body with the given status.
func (s *Server) writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if v == nil {
		return
	}
	if err := json.NewEncoder(w).Encode(v); err != nil {
		// The status line is already sent, so this can only be logged.
		s.logger.Error("writing http response body failed", "error", err)
	}
}

// writeError maps a domain error onto its HTTP status and JSON envelope.
func (s *Server) writeError(w http.ResponseWriter, r *http.Request, err error) {
	status, body := classify(err)
	// 501 is a machine where approving takes a command app-tail cannot run itself: a sentence
	// the caller acts on, like everything below 500, rather than a fault to look up in the log.
	if status >= http.StatusInternalServerError && status != statusApproveByHand {
		body.Ref = errorRef()
		s.logger.Error("api request failed",
			"method", r.Method, "path", r.URL.Path, "ref", body.Ref, "error", err)
	} else {
		s.logger.Debug("api request rejected",
			"method", r.Method, "path", r.URL.Path, "status", status, "error", err)
	}
	// The log line above keeps the whole sentence; what goes back over the wire does not
	// describe the machine it came from.
	body.Error = redactMachinePaths(body.Error)
	s.writeJSON(w, status, body)
}

// errorRef is the handle a caller quotes to find the failure in the log.
func errorRef() string {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand does not fail on any platform this runs on, and a reference that
		// matches nothing is worse than none at all.
		return ""
	}
	return hex.EncodeToString(b[:])
}

// machinePath matches an absolute filesystem path, over both separators, and only where one
// starts: the leading group is what keeps the path half of a URL out of it. A segment may
// hold single spaces, because the directories this app keeps state in on macOS do -- and a
// space is only taken as part of the path when what follows it is another segment and a
// separator, which is what stops the match running off into the sentence around it.
var machinePath = regexp.MustCompile(
	`(^|[\s"'(\[=,])((?:[A-Za-z]:)?[/\\](?:[^\s/\\]+(?: [^\s/\\]+)*[/\\])+[^\s/\\]*)`)

// redactMachinePaths cuts absolute paths in an error message down to their last segment.
//
// An error nothing anticipated carries whatever the operating system put into it, and on
// this machine that is routinely the account name, the state directory and the path of the
// socket the privileged side listens on. The sentence is what makes a failure actionable and
// is kept whole; what goes is the part that describes this machine rather than the failure.
func redactMachinePaths(msg string) string {
	found := machinePath.FindAllStringSubmatchIndex(msg, -1)
	if len(found) == 0 {
		return msg
	}
	var out strings.Builder
	end := 0
	for _, at := range found {
		start, stop := at[4], at[5]
		out.WriteString(msg[end:start])
		out.WriteString(lastSegment(msg[start:stop]))
		end = stop
	}
	out.WriteString(msg[end:])
	return out.String()
}

// lastSegment is one path as the name at the end of it, keeping whatever punctuation the
// surrounding sentence put after it.
func lastSegment(path string) string {
	trailing := ""
	for len(path) > 0 && strings.ContainsRune(`:,;.)]"'`, rune(path[len(path)-1])) {
		trailing = path[len(path)-1:] + trailing
		path = path[:len(path)-1]
	}
	named := strings.TrimRight(path, `/\`)
	// A path that named a directory keeps saying so.
	trailing = path[len(named):] + trailing
	if cut := strings.LastIndexAny(named, `/\`); cut >= 0 {
		return ".../" + named[cut+1:] + trailing
	}
	return named + trailing
}

// classify turns an error into its status code and response body. The mapping is
// the API's contract with the dashboard, so it lives in one place.
func classify(err error) (int, errorBody) {
	var conflict *config.ConflictError
	if errors.As(err, &conflict) {
		return http.StatusConflict, errorBody{
			Error: err.Error(),
			Conflict: &conflictBody{
				Endpoint:  conflict.Endpoint,
				ForwardID: conflict.OtherID,
				Name:      conflict.OtherName,
			},
		}
	}

	var validation *config.ValidationError
	if errors.As(err, &validation) {
		return http.StatusBadRequest, errorBody{Error: err.Error(), Field: validation.Field}
	}

	if errors.Is(err, config.ErrNotFound) {
		return http.StatusNotFound, errorBody{Error: err.Error()}
	}

	if errors.Is(err, ErrApprovalDeclined) {
		return http.StatusConflict, errorBody{Error: err.Error()}
	}
	var byHand *approvalByHandError
	if errors.As(err, &byHand) {
		return statusApproveByHand, errorBody{Error: err.Error()}
	}

	var unavailable *unavailableError
	if errors.As(err, &unavailable) {
		return http.StatusServiceUnavailable, errorBody{Error: err.Error()}
	}

	// A node that is down or mid-restart is a temporary condition the caller should
	// retry, not a fault in the agent.
	if errors.Is(err, tsnode.ErrNotRunning) {
		return http.StatusServiceUnavailable, errorBody{Error: err.Error()}
	}

	return http.StatusInternalServerError, errorBody{Error: err.Error()}
}

// decodeJSON reads a request body into v, rejecting unknown fields so a typo in a
// client payload surfaces as a 400 instead of being silently dropped.
func decodeJSON(r *http.Request, v any) error {
	dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body, maxRequestBytes))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return badRequest("could not parse JSON body: %v", err)
	}
	return nil
}

// require returns a 503-mapped error when an optional dependency is missing, so a
// partially wired agent answers clearly rather than panicking.
func require(dep any, name string) error {
	if dep == nil {
		return Unavailable(name, "not wired into this agent")
	}
	return nil
}

// discardLogger is used when a caller supplies no logger.
func discardLogger() *slog.Logger {
	return slog.New(slog.DiscardHandler)
}
