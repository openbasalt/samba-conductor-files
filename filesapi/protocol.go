// Package filesapi is the protocol between conductor (the only client) and
// the conductor-files agent on a domain-member file server. It holds the
// types, their validation, the framing, the TLS identities and pins, and a
// client, so conductor can import it without the agent.
//
// Transport: TCP with TLS 1.3 and client certificates. Neither side uses a
// certificate authority: each pins the other's public key (the SHA-256 of
// its SubjectPublicKeyInfo, see Pin). The agent learns conductor's key at
// enrollment (a one-time code made on the file server, see EnrollmentCode);
// conductor learns the agent's key from that code.
//
// Framing: one request and one response per connection, each one JSON
// object on one line, at most MaxMessageSize bytes. Requests name an
// allowlisted operation; parameters are decoded strictly (unknown fields
// rejected) and validated on both sides. Every request carries the acting
// AD user, which conductor has checked (role, fresh second factor for
// writes) and which the agent writes to its own hash-chained audit log.
package filesapi

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"time"
)

// ProtocolVersion is bumped on incompatible changes.
const ProtocolVersion = 1

// DefaultPort is where the agent listens.
const DefaultPort = 7443

// MaxMessageSize bounds one framed message.
const MaxMessageSize = 4 << 20

// Op names an allowlisted operation.
type Op string

// Operations.
const (
	// OpEnroll pins the caller's key with a one-time token (the only
	// operation an unpinned caller may use).
	OpEnroll Op = "enroll"
	// OpUnenroll drops the caller's own pin (revocation from conductor).
	OpUnenroll        Op = "unenroll"
	OpStatus          Op = "status"
	OpDirsList        Op = "dirs.list"
	OpGroupsResolve   Op = "groups.resolve"
	OpSharesList      Op = "shares.list"
	OpShareGet        Op = "share.get"
	OpSharePlan       Op = "share.plan"
	OpShareApply      Op = "share.apply"
	OpShareRemovePlan Op = "share.remove_plan"
	OpShareRemove     Op = "share.remove"
	OpSessionsList    Op = "sessions.list"
)

// Mutating reports whether the operation changes the server.
func (o Op) Mutating() bool {
	switch o {
	case OpEnroll, OpUnenroll, OpShareApply, OpShareRemove:
		return true
	}
	return false
}

// Actor is the signed-in conductor user a request is made for.
type Actor struct {
	// User is the AD sAMAccountName.
	User string `json:"user"`
	SID  string `json:"sid"`
	// Session is an opaque identifier of the web session (not the cookie).
	Session string `json:"session"`
	IP      string `json:"ip,omitempty"`
}

// String renders the actor for audit logs.
func (a Actor) String() string {
	s := "conductor:" + a.User
	if a.IP != "" {
		s += "@" + a.IP
	}
	return s
}

// Request is one call.
type Request struct {
	Version int             `json:"version"`
	ID      string          `json:"id"`
	Op      Op              `json:"op"`
	Actor   Actor           `json:"actor"`
	Params  json.RawMessage `json:"params,omitempty"`
	SentAt  time.Time       `json:"sent_at"`
}

// ErrorCode classifies a failed call.
type ErrorCode string

// Error codes.
const (
	CodeBadRequest  ErrorCode = "bad_request"
	CodeInvalid     ErrorCode = "invalid"   // validation failed; Details lists why
	CodeNotFound    ErrorCode = "not_found" // share or directory unknown
	CodeConflict    ErrorCode = "conflict"  // the state changed since the plan
	CodeForbidden   ErrorCode = "forbidden" // e.g. a share not managed by conductor-files
	CodeNotEnrolled ErrorCode = "not_enrolled"
	CodeUnavailable ErrorCode = "unavailable"
	CodeFailed      ErrorCode = "failed"
	CodeVersion     ErrorCode = "version"
)

// Error is the error part of a Response.
type Error struct {
	Code    ErrorCode `json:"code"`
	Message string    `json:"message"`
	Details []string  `json:"details,omitempty"`
}

func (e *Error) Error() string { return fmt.Sprintf("conductor-files: %s: %s", e.Code, e.Message) }

// ErrorCodeOf returns the API error code of err ("" when it is not one).
func ErrorCodeOf(err error) ErrorCode {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}

// Response answers a Request with the same ID.
type Response struct {
	Version int             `json:"version"`
	ID      string          `json:"id"`
	OK      bool            `json:"ok"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *Error          `json:"error,omitempty"`
}

// Params is implemented by every parameter type.
type Params interface{ Validate() error }

// NoParams is used by operations without parameters.
type NoParams struct{}

// Validate implements Params.
func (NoParams) Validate() error { return nil }

// Allowlist maps each operation to a constructor of its parameter type.
var Allowlist = map[Op]func() Params{
	OpEnroll:          func() Params { return &EnrollParams{} },
	OpUnenroll:        func() Params { return &NoParams{} },
	OpStatus:          func() Params { return &NoParams{} },
	OpDirsList:        func() Params { return &DirsListParams{} },
	OpGroupsResolve:   func() Params { return &GroupsResolveParams{} },
	OpSharesList:      func() Params { return &NoParams{} },
	OpShareGet:        func() Params { return &ShareNameParams{} },
	OpSharePlan:       func() Params { return &SharePlanParams{} },
	OpShareApply:      func() Params { return &SharePlanParams{} },
	OpShareRemovePlan: func() Params { return &ShareNameParams{} },
	OpShareRemove:     func() Params { return &ShareNameParams{} },
	OpSessionsList:    func() Params { return &NoParams{} },
}

var (
	idRE   = regexp.MustCompile(`^[A-Za-z0-9_-]{8,64}$`)
	userRE = regexp.MustCompile(`^[^\x00-\x1f]{1,256}$`)
	sidRE  = regexp.MustCompile(`^S-1-[0-9]+(-[0-9]+){1,15}$`)
)

// NewRequest builds a validated request.
func NewRequest(id string, op Op, actor Actor, params Params) (Request, error) {
	if params == nil {
		params = NoParams{}
	}
	raw, err := json.Marshal(params)
	if err != nil {
		return Request{}, err
	}
	req := Request{Version: ProtocolVersion, ID: id, Op: op, Actor: actor, Params: raw, SentAt: time.Now().UTC()}
	if _, err := req.Decode(); err != nil {
		return Request{}, err
	}
	return req, nil
}

// Decode validates the envelope and decodes the typed parameters.
func (r Request) Decode() (Params, error) {
	if r.Version != ProtocolVersion {
		return nil, &Error{Code: CodeVersion, Message: fmt.Sprintf("protocol version %d, want %d", r.Version, ProtocolVersion)}
	}
	if !idRE.MatchString(r.ID) {
		return nil, &Error{Code: CodeBadRequest, Message: "invalid request id"}
	}
	if !userRE.MatchString(r.Actor.User) || r.Actor.Session == "" || len(r.Actor.Session) > 128 || len(r.Actor.IP) > 64 {
		return nil, &Error{Code: CodeBadRequest, Message: "the actor (user and session) is required"}
	}
	if !sidRE.MatchString(r.Actor.SID) {
		return nil, &Error{Code: CodeBadRequest, Message: "the actor SID is invalid"}
	}
	mk, ok := Allowlist[r.Op]
	if !ok {
		return nil, &Error{Code: CodeBadRequest, Message: fmt.Sprintf("operation %q is not allowlisted", r.Op)}
	}
	p := mk()
	params := r.Params
	if len(params) == 0 || string(params) == "null" {
		params = json.RawMessage("{}")
	}
	dec := json.NewDecoder(bytes.NewReader(params))
	dec.DisallowUnknownFields()
	if err := dec.Decode(p); err != nil {
		return nil, &Error{Code: CodeBadRequest, Message: "params: " + err.Error()}
	}
	if dec.More() {
		return nil, &Error{Code: CodeBadRequest, Message: "params: trailing data"}
	}
	if err := p.Validate(); err != nil {
		var ve *ValidationError
		if errors.As(err, &ve) {
			return nil, &Error{Code: CodeInvalid, Message: "the request is not valid", Details: ve.Problems}
		}
		return nil, &Error{Code: CodeBadRequest, Message: err.Error()}
	}
	return p, nil
}

// OKResponse builds a successful response.
func OKResponse(id string, result any) (Response, error) {
	raw, err := json.Marshal(result)
	if err != nil {
		return Response{}, err
	}
	return Response{Version: ProtocolVersion, ID: id, OK: true, Result: raw}, nil
}

// ErrorResponse builds a failed response.
func ErrorResponse(id string, e *Error) Response {
	return Response{Version: ProtocolVersion, ID: id, Error: e}
}

// DecodeResult decodes a successful response's result into out, or returns
// the response's error.
func DecodeResult(resp Response, out any) error {
	if !resp.OK {
		if resp.Error != nil {
			return resp.Error
		}
		return &Error{Code: CodeFailed, Message: "failed without an error"}
	}
	if out == nil {
		return nil
	}
	dec := json.NewDecoder(bytes.NewReader(resp.Result))
	dec.DisallowUnknownFields()
	return dec.Decode(out)
}

// ErrTooLarge is returned for a message beyond MaxMessageSize.
var ErrTooLarge = errors.New("filesapi: message too large")

// WriteMessage frames v as one JSON line.
func WriteMessage(w io.Writer, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if len(b)+1 > MaxMessageSize {
		return ErrTooLarge
	}
	_, err = w.Write(append(b, '\n'))
	return err
}

// ReadMessage reads one framed message into v (unknown fields rejected).
func ReadMessage(r *bufio.Reader, v any) error {
	var line []byte
	for {
		chunk, isPrefix, err := r.ReadLine()
		if err != nil {
			return err
		}
		line = append(line, chunk...)
		if len(line) > MaxMessageSize {
			return ErrTooLarge
		}
		if !isPrefix {
			break
		}
	}
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}
