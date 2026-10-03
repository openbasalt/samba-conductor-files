// Command conductor-files is the Samba Conductor agent for domain-member
// file servers. See the repository README and docs/install.md.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/openbasalt/samba-conductor-files/filesapi"
	"github.com/openbasalt/samba-conductor-files/internal/agent"
	"github.com/openbasalt/samba-conductor-files/internal/audit"
	"github.com/openbasalt/samba-conductor-files/internal/config"
	"github.com/openbasalt/samba-conductor-files/internal/fsguard"
	"github.com/openbasalt/samba-conductor-files/internal/samba"
)

// version is set at build time (-X main.version=...).
var version = ""

func buildVersion() string {
	if version != "" {
		return version
	}
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		return bi.Main.Version
	}
	return "dev"
}

const usage = `conductor-files: Samba Conductor agent for domain-member file servers

Usage:
  conductor-files serve        [--config FILE]
  conductor-files enroll-code  [--config FILE] [--ttl 1h] [--quiet]
  conductor-files enroll-cancel [--config FILE]
  conductor-files trust list   [--config FILE]
  conductor-files trust remove [--config FILE] PIN
  conductor-files check        [--config FILE]
  conductor-files audit verify [--config FILE]
  conductor-files version
`

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "conductor-files:", err)
		var ec exitCode
		if errors.As(err, &ec) {
			os.Exit(int(ec))
		}
		os.Exit(1)
	}
}

type exitCode int

func (e exitCode) Error() string { return fmt.Sprintf("exit status %d", int(e)) }

func run(args []string, out io.Writer) error {
	if len(args) == 0 {
		fmt.Fprint(out, usage)
		return exitCode(2)
	}
	cmd, rest := args[0], args[1:]
	if (cmd == "trust" || cmd == "audit") && len(rest) > 0 {
		cmd, rest = cmd+" "+rest[0], rest[1:]
	}
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	cfgPath := fs.String("config", config.DefaultPath, "configuration file")
	ttl := fs.Duration("ttl", 0, "validity of the enrollment code (default from the configuration, 1h)")
	quiet := fs.Bool("quiet", false, "print only the enrollment code")
	if err := fs.Parse(rest); err != nil {
		return exitCode(2)
	}
	switch cmd {
	case "version":
		fmt.Fprintln(out, "conductor-files", buildVersion())
		return nil
	case "help", "-h", "--help":
		fmt.Fprint(out, usage)
		return nil
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	switch cmd {
	case "serve":
		return serve(cfg)
	case "enroll-code":
		return enrollCode(cfg, *ttl, *quiet, out)
	case "enroll-cancel":
		return agent.NewTrust(cfg.State.Dir, cfg.Enrollment.MaxFailures).CancelCode()
	case "trust list":
		return trustList(cfg, out)
	case "trust remove":
		if fs.NArg() != 1 || !filesapi.ValidPin(fs.Arg(0)) {
			return errors.New("usage: conductor-files trust remove sha256:<pin>")
		}
		return trustRemove(cfg, fs.Arg(0), out)
	case "check":
		return check(cfg, out)
	case "audit verify":
		n, err := audit.Verify(filepath.Join(cfg.State.Dir, "audit.log"))
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		fmt.Fprintf(out, "audit log intact: %d entries\n", n)
		return nil
	}
	fmt.Fprint(out, usage)
	return exitCode(2)
}

// stateDir checks the state directory (root, 0700).
func stateDir(cfg *config.Config) error {
	st, err := os.Stat(cfg.State.Dir)
	if err != nil {
		return fmt.Errorf("state directory: %w", err)
	}
	if !st.IsDir() || st.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("state directory %s must have mode 0700", cfg.State.Dir)
	}
	return nil
}

func tools() samba.Tools { return samba.Tools{R: samba.ExecRunner{Timeout: 2 * time.Minute}} }

func newAgent(cfg *config.Config, log *slog.Logger) (*agent.Agent, filesapi.Identity, error) {
	if err := stateDir(cfg); err != nil {
		return nil, filesapi.Identity{}, err
	}
	id, err := filesapi.LoadOrCreateIdentity(cfg.State.Dir, cfg.Server.Name)
	if err != nil {
		return nil, id, err
	}
	al, err := audit.Open(filepath.Join(cfg.State.Dir, "audit.log"))
	if err != nil {
		return nil, id, err
	}
	t := tools()
	t.P = cfg.Samba
	a := agent.New(agent.Options{Config: cfg, Samba: t, Guard: fsguard.Guard{Roots: cfg.Shares.Roots}, ID: id, Audit: al,
		Trust: agent.NewTrust(cfg.State.Dir, cfg.Enrollment.MaxFailures), Logger: log, Version: buildVersion()})
	return a, id, nil
}

func serve(cfg *config.Config) error {
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	t := tools()
	t.P = cfg.Samba
	if err := agent.CheckNotDomainController(ctx, t); err != nil {
		return err
	}
	a, id, err := newAgent(cfg, log)
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", cfg.Server.Listen)
	if err != nil {
		return err
	}
	trusted, _ := agent.NewTrust(cfg.State.Dir, cfg.Enrollment.MaxFailures).List()
	log.Info("conductor-files listening", "version", buildVersion(), "listen", cfg.Server.Listen, "key", id.Pin,
		"roots", cfg.Shares.Roots, "trusted_conductors", len(trusted))
	st := a.Status(ctx)
	for _, c := range st.Checks {
		if !c.OK {
			log.Warn("prerequisite not met (changes are refused until fixed)", "check", c.Name, "detail", c.Detail)
		}
	}
	return a.Serve(ctx, ln)
}

func enrollCode(cfg *config.Config, ttl time.Duration, quiet bool, out io.Writer) error {
	if err := stateDir(cfg); err != nil {
		return err
	}
	id, err := filesapi.LoadOrCreateIdentity(cfg.State.Dir, cfg.Server.Name)
	if err != nil {
		return err
	}
	if ttl == 0 {
		ttl = cfg.Enrollment.TTL.Duration
	}
	if ttl < time.Minute || ttl > 24*time.Hour {
		return errors.New("--ttl must be 1m-24h")
	}
	tr := agent.NewTrust(cfg.State.Dir, cfg.Enrollment.MaxFailures)
	token, exp, err := tr.NewCode(ttl)
	if err != nil {
		return err
	}
	if al, err := audit.Open(filepath.Join(cfg.State.Dir, "audit.log")); err == nil {
		_ = al.Append(audit.Entry{Actor: "local:" + localUser(), Op: "enroll_code", Result: audit.ResultOK,
			Detail: "enrollment code issued, valid until " + exp.Format(time.RFC3339)})
	}
	code := filesapi.FormatEnrollmentCode(token, id.Pin)
	if quiet {
		fmt.Fprintln(out, code)
		return nil
	}
	_, port, _ := net.SplitHostPort(cfg.Server.Listen)
	fmt.Fprintf(out, "Enrollment code for %s (single use, valid until %s):\n\n  %s\n\n", cfg.Server.Name, exp.Local().Format("2006-01-02 15:04 MST"), code)
	fmt.Fprintf(out, "In Samba Conductor: File servers > Add a file server, address %s:%s, then paste the code.\n", cfg.Server.Name, port)
	fmt.Fprintf(out, "This server's key: %s (the code carries it; conductor pins it).\n", id.Pin)
	return nil
}

func localUser() string {
	if u := os.Getenv("SUDO_USER"); u != "" {
		return u + " (sudo)"
	}
	return fmt.Sprintf("uid %d", os.Getuid())
}

func trustList(cfg *config.Config, out io.Writer) error {
	list, err := agent.NewTrust(cfg.State.Dir, cfg.Enrollment.MaxFailures).List()
	if err != nil {
		return err
	}
	if len(list) == 0 {
		fmt.Fprintln(out, "no conductor is enrolled")
		return nil
	}
	w := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "PIN\tNAME\tENROLLED\tBY")
	for _, c := range list {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", c.Pin, c.Name, c.EnrolledAt.Local().Format(time.RFC3339), c.EnrolledBy)
	}
	return w.Flush()
}

func trustRemove(cfg *config.Config, pin string, out io.Writer) error {
	removed, err := agent.NewTrust(cfg.State.Dir, cfg.Enrollment.MaxFailures).Remove(pin)
	if err != nil {
		return err
	}
	if !removed {
		return errors.New("no enrolled conductor has that pin")
	}
	if al, err := audit.Open(filepath.Join(cfg.State.Dir, "audit.log")); err == nil {
		_ = al.Append(audit.Entry{Actor: "local:" + localUser(), Op: "trust_remove", Target: pin, Result: audit.ResultOK})
	}
	fmt.Fprintln(out, "removed; that conductor can no longer reach this agent")
	return nil
}

func check(cfg *config.Config, out io.Writer) error {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	a, id, err := newAgent(cfg, log)
	if err != nil {
		return err
	}
	st := a.Status(context.Background())
	fmt.Fprintf(out, "%s: conductor-files %s, Samba %s, domain %s (%s)\nkey %s\n", st.Hostname, st.Version, st.SambaVersion, st.Domain, st.Realm, id.Pin)
	for _, c := range st.Checks {
		mark := "ok  "
		if !c.OK {
			mark = "FAIL"
		}
		fmt.Fprintf(out, "  %s %-16s %s\n", mark, c.Name, c.Detail)
	}
	if !st.Ready() {
		return exitCode(1)
	}
	return nil
}
