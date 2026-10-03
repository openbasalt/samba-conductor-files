// Package agent is `conductor-files serve`: the TLS listener conductor
// talks to, the typed operations, the share planner and the audit trail.
//
// Security:
//   - TLS 1.3 with client certificates; a client key is accepted only when
//     it is pinned (trust.json), or while an enrollment code is outstanding,
//     and then only for the enroll operation;
//   - requests are typed and allowlisted, decoded strictly, size-bounded;
//   - Samba programs run with fixed paths and argument lists built from
//     validated values (package samba), paths are checked by fsguard;
//   - every change is planned first; an apply re-plans and proceeds only
//     when the digest of the reviewed plan still matches;
//   - every change and every refused request goes to the hash-chained audit
//     log with the AD user conductor acted for and the client key's pin.
package agent

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/samba-conductor/conductor-files/filesapi"
	"github.com/samba-conductor/conductor-files/internal/audit"
	"github.com/samba-conductor/conductor-files/internal/config"
	"github.com/samba-conductor/conductor-files/internal/fsguard"
	"github.com/samba-conductor/conductor-files/internal/samba"
)

// Samba is what the agent needs from the Samba programs (samba.Tools;
// tests use a fake).
type Samba interface {
	Registry(ctx context.Context) ([]samba.Section, error)
	Effective(ctx context.Context) ([]samba.Section, error)
	Parameter(ctx context.Context, name string) (string, error)
	Version(ctx context.Context) (string, error)
	ShareSecView(ctx context.Context, share string) (string, error)
	NTACLGet(ctx context.Context, path string) (string, error)
	LookupSID(ctx context.Context, sid string) (string, int, error)
	Domain(ctx context.Context) (samba.DomainInfo, error)
	TrustOK(ctx context.Context) error
	StatusJSON(ctx context.Context) ([]byte, error)
	RunArgs(ctx context.Context, argv []string) error
	ImportArgs(file, share string) []string
	DelShareArgs(share string) []string
	ShareSecReplaceArgs(share, acl string) []string
	ShareSecDeleteArgs(share string) []string
	NTACLSetArgs(sddl, path string) []string
	ReloadArgs() []string
}

// Agent serves conductor.
type Agent struct {
	cfg     *config.Config
	sb      Samba
	guard   fsguard.Guard
	trust   *Trust
	audit   *audit.Log
	id      filesapi.Identity
	log     *slog.Logger
	version string
	now     func() time.Time
	// writeMu serialises changes (one apply at a time).
	writeMu sync.Mutex
	sem     chan struct{}
	wg      sync.WaitGroup
	// readSmbConf reads the main Samba configuration (tests replace it).
	readSmbConf func() ([]byte, error)
}

// Options configure an agent.
type Options struct {
	Config  *config.Config
	Samba   Samba
	Guard   fsguard.Guard
	Trust   *Trust
	Audit   *audit.Log
	ID      filesapi.Identity
	Logger  *slog.Logger
	Version string
}

// New builds an agent (not listening yet).
func New(o Options) *Agent {
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	a := &Agent{cfg: o.Config, sb: o.Samba, guard: o.Guard, trust: o.Trust, audit: o.Audit, id: o.ID, log: o.Logger,
		version: o.Version, now: time.Now, sem: make(chan struct{}, o.Config.Server.MaxConnections)}
	a.readSmbConf = func() ([]byte, error) { return os.ReadFile(a.cfg.State.SmbConf) }
	return a
}

// importDir holds the share sections handed to `net conf import`.
func (a *Agent) importDir() string { return filepath.Join(a.cfg.State.Dir, "import") }

// TLSConfig is the listener's configuration: TLS 1.3, a client key is
// required and must be pinned (or an enrollment code outstanding).
func (a *Agent) TLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{a.id.Cert},
		ClientAuth:   tls.RequireAnyClientCert,
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			if len(raw) == 0 {
				return errors.New("no client certificate")
			}
			cert, err := x509.ParseCertificate(raw[0])
			if err != nil {
				return err
			}
			pin := filesapi.PinOf(cert)
			if a.trust.Pinned(pin) || a.trust.Pending() {
				return nil
			}
			a.log.Warn("refused an untrusted client key", "pin", pin)
			return errors.New("untrusted client key")
		},
	}
}

// Timeouts of one connection.
const (
	handshakeTimeout = 15 * time.Second
	requestTimeout   = 10 * time.Minute
)

// Serve accepts connections on ln (plain TCP; TLS is added here) until ctx
// ends.
func (a *Agent) Serve(ctx context.Context, ln net.Listener) error {
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	conf := a.TLSConfig()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				a.wg.Wait()
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				time.Sleep(100 * time.Millisecond)
				continue
			}
			return err
		}
		select {
		case a.sem <- struct{}{}:
		default:
			a.log.Warn("too many connections; refusing one", "remote", conn.RemoteAddr().String())
			_ = conn.Close()
			continue
		}
		a.wg.Add(1)
		go func() {
			defer a.wg.Done()
			defer func() { <-a.sem }()
			a.serveConn(ctx, tls.Server(conn, conf))
		}()
	}
}

func (a *Agent) serveConn(ctx context.Context, conn *tls.Conn) {
	defer func() { _ = conn.Close() }()
	remote := conn.RemoteAddr().String()
	_ = conn.SetDeadline(a.now().Add(handshakeTimeout))
	if err := conn.HandshakeContext(ctx); err != nil {
		a.log.Info("TLS handshake failed", "remote", remote, "err", err)
		return
	}
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return
	}
	pin := filesapi.PinOf(certs[0])
	_ = conn.SetDeadline(a.now().Add(requestTimeout))
	var req filesapi.Request
	if err := filesapi.ReadMessage(bufio.NewReaderSize(conn, 64<<10), &req); err != nil {
		a.log.Info("unreadable request", "remote", remote, "err", err)
		_ = filesapi.WriteMessage(conn, filesapi.ErrorResponse("", &filesapi.Error{Code: filesapi.CodeBadRequest, Message: "unreadable request"}))
		return
	}
	rctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	resp := a.Handle(rctx, pin, remote, req)
	if err := filesapi.WriteMessage(conn, resp); err != nil {
		a.log.Info("writing the response failed", "remote", remote, "err", err)
	}
}

// Handle answers one request from the client key pin.
func (a *Agent) Handle(ctx context.Context, pin, remote string, req filesapi.Request) filesapi.Response {
	start := a.now()
	params, err := req.Decode()
	if err != nil {
		var e *filesapi.Error
		if !errors.As(err, &e) {
			e = &filesapi.Error{Code: filesapi.CodeBadRequest, Message: err.Error()}
		}
		return filesapi.ErrorResponse(req.ID, e)
	}
	if req.Op != filesapi.OpEnroll && !a.trust.Pinned(pin) {
		a.record(req, pin, "", audit.ResultDenied, "client key not enrolled (from "+remote+")", "", nil)
		return filesapi.ErrorResponse(req.ID, &filesapi.Error{Code: filesapi.CodeNotEnrolled, Message: "this client key is not enrolled"})
	}
	result, apiErr := a.dispatch(ctx, pin, req, params)
	a.log.Info("request", "op", req.Op, "actor", req.Actor.String(), "ok", apiErr == nil, "took", a.now().Sub(start).Round(time.Millisecond))
	if apiErr != nil {
		return filesapi.ErrorResponse(req.ID, apiErr)
	}
	resp, err := filesapi.OKResponse(req.ID, result)
	if err != nil {
		return filesapi.ErrorResponse(req.ID, &filesapi.Error{Code: filesapi.CodeFailed, Message: err.Error()})
	}
	return resp
}

func (a *Agent) dispatch(ctx context.Context, pin string, req filesapi.Request, params filesapi.Params) (any, *filesapi.Error) {
	switch req.Op {
	case filesapi.OpEnroll:
		return a.enroll(req, pin, params.(*filesapi.EnrollParams))
	case filesapi.OpUnenroll:
		return a.unenroll(req, pin)
	case filesapi.OpStatus:
		return a.Status(ctx), nil
	case filesapi.OpDirsList:
		return a.dirsList(ctx, params.(*filesapi.DirsListParams))
	case filesapi.OpGroupsResolve:
		return a.groupsResolve(ctx, params.(*filesapi.GroupsResolveParams))
	case filesapi.OpSharesList:
		return a.sharesList(ctx)
	case filesapi.OpShareGet:
		return a.shareGet(ctx, params.(*filesapi.ShareNameParams).Name)
	case filesapi.OpSharePlan:
		p := params.(*filesapi.SharePlanParams)
		pl, apiErr := a.planShare(ctx, p.Spec, p.Create)
		if apiErr != nil {
			return nil, apiErr
		}
		return pl.plan, nil
	case filesapi.OpShareApply:
		return a.applyShare(ctx, req, pin, params.(*filesapi.SharePlanParams))
	case filesapi.OpShareRemovePlan:
		pl, apiErr := a.planRemove(ctx, params.(*filesapi.ShareNameParams).Name)
		if apiErr != nil {
			return nil, apiErr
		}
		return pl.plan, nil
	case filesapi.OpShareRemove:
		return a.applyRemove(ctx, req, pin, params.(*filesapi.ShareNameParams))
	case filesapi.OpSessionsList:
		return a.sessions(ctx)
	}
	return nil, &filesapi.Error{Code: filesapi.CodeBadRequest, Message: "unknown operation"}
}

// record writes one audit entry (failures to audit are logged loudly).
func (a *Agent) record(req filesapi.Request, pin, target, result, detail, digest string, steps []string) {
	if len(detail) > 4000 {
		detail = detail[:4000] + "..."
	}
	e := audit.Entry{Actor: req.Actor.String(), ActorSID: req.Actor.SID, Session: req.Actor.Session, Peer: pin,
		Op: string(req.Op), Target: target, Result: result, Detail: detail, Digest: digest, Steps: steps}
	if err := a.audit.Append(e); err != nil {
		a.log.Error("AUDIT WRITE FAILED", "op", req.Op, "err", err)
	}
}

// ---- enrollment ----

func (a *Agent) enroll(req filesapi.Request, pin string, p *filesapi.EnrollParams) (any, *filesapi.Error) {
	a.writeMu.Lock()
	defer a.writeMu.Unlock()
	err := a.trust.Enroll(p.Token, pin, p.Name, req.Actor.String())
	if err != nil {
		a.record(req, pin, p.Name, audit.ResultDenied, err.Error(), "", nil)
		code := filesapi.CodeForbidden
		if !errors.Is(err, ErrNoCode) && !errors.Is(err, ErrExpired) && !errors.Is(err, ErrWrongToken) && !errors.Is(err, ErrBurned) {
			code = filesapi.CodeFailed
		}
		return nil, &filesapi.Error{Code: code, Message: err.Error()}
	}
	a.record(req, pin, p.Name, audit.ResultOK, "pinned conductor key "+pin, "", nil)
	a.log.Info("enrolled a conductor", "name", p.Name, "pin", pin, "by", req.Actor.String())
	return filesapi.EnrollResult{Hostname: a.cfg.Server.Name, AgentPin: a.id.Pin, Version: a.version}, nil
}

func (a *Agent) unenroll(req filesapi.Request, pin string) (any, *filesapi.Error) {
	a.writeMu.Lock()
	defer a.writeMu.Unlock()
	removed, err := a.trust.Remove(pin)
	if err != nil {
		a.record(req, pin, pin, audit.ResultFailed, err.Error(), "", nil)
		return nil, &filesapi.Error{Code: filesapi.CodeFailed, Message: err.Error()}
	}
	a.record(req, pin, pin, audit.ResultOK, fmt.Sprintf("unpinned the caller's key (was pinned: %v)", removed), "", nil)
	return map[string]bool{"removed": removed}, nil
}
