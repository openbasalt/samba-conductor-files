// Package config loads /etc/conductor-files/agent.toml. Unknown keys are an
// error. Everything a request could misuse (roots, programs, the shadow
// copy profile) is host configuration, written by root; requests can only
// pick among what it allows.
package config

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/BurntSushi/toml"

	"github.com/samba-conductor/conductor-files/filesapi"
	"github.com/samba-conductor/conductor-files/internal/samba"
)

// DefaultPath is where the agent reads its configuration.
const DefaultPath = "/etc/conductor-files/agent.toml"

// Config is the whole file.
type Config struct {
	Server       Server       `toml:"server"`
	Shares       Shares       `toml:"shares"`
	ShadowCopies ShadowCopies `toml:"shadow_copies"`
	Samba        samba.Paths  `toml:"samba"`
	State        State        `toml:"state"`
	Enrollment   Enrollment   `toml:"enrollment"`
}

// Server is the TLS listener.
type Server struct {
	// Listen address, default ":7443".
	Listen string `toml:"listen"`
	// Name is the host name reported to conductor and the certificate's
	// common name (default: the system host name).
	Name string `toml:"name"`
	// MaxConnections served at once.
	MaxConnections int `toml:"max_connections"`
}

// Shares are the directories shares may be created below.
type Shares struct {
	Roots []string `toml:"roots"`
}

// ShadowCopies is the vfs_shadow_copy2 profile offered as "previous
// versions". Off unless snapdir and format are set: snapshots depend on the
// file system (btrfs, ZFS, LVM) and their naming.
type ShadowCopies struct {
	Snapdir   string `toml:"snapdir"`
	Format    string `toml:"format"`
	Sort      string `toml:"sort"`
	Localtime bool   `toml:"localtime"`
}

// Enabled reports whether the profile is configured.
func (s ShadowCopies) Enabled() bool { return s.Snapdir != "" && s.Format != "" }

// State is the agent's private directory.
type State struct {
	Dir string `toml:"dir"`
	// SmbConf is the main Samba configuration, read (never written) to
	// check that registry shares are included.
	SmbConf string `toml:"smb_conf"`
}

// Enrollment bounds one-time enrollment codes.
type Enrollment struct {
	// TTL of a code (default 1 h, at most 24 h).
	TTL Duration `toml:"ttl"`
	// MaxFailures burns a code after this many wrong tokens (default 5).
	MaxFailures int `toml:"max_failures"`
}

// Duration reads "90m"-style values.
type Duration struct{ time.Duration }

// UnmarshalText implements encoding.TextUnmarshaler.
func (d *Duration) UnmarshalText(b []byte) error {
	v, err := time.ParseDuration(string(b))
	d.Duration = v
	return err
}

// Default returns the defaults every file starts from.
func Default() *Config {
	return &Config{
		Server:     Server{Listen: fmt.Sprintf(":%d", filesapi.DefaultPort), MaxConnections: 16},
		Samba:      samba.DefaultPaths(),
		State:      State{Dir: "/var/lib/conductor-files", SmbConf: "/etc/samba/smb.conf"},
		Enrollment: Enrollment{TTL: Duration{time.Hour}, MaxFailures: 5},
	}
}

// Load reads and validates a file.
func Load(p string) (*Config, error) {
	c := Default()
	md, err := toml.DecodeFile(p, c)
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	if und := md.Undecoded(); len(und) > 0 {
		keys := make([]string, len(und))
		for i, k := range und {
			keys[i] = k.String()
		}
		return nil, fmt.Errorf("config: unknown keys: %s", strings.Join(keys, ", "))
	}
	if c.Server.Name == "" {
		h, err := os.Hostname()
		if err != nil {
			return nil, err
		}
		c.Server.Name = h
	}
	return c, c.Validate()
}

// Validate checks the values.
func (c *Config) Validate() error {
	var errs []error
	bad := func(format string, a ...any) { errs = append(errs, fmt.Errorf("config: "+format, a...)) }
	if _, _, err := net.SplitHostPort(c.Server.Listen); err != nil {
		bad("server.listen %q: %v", c.Server.Listen, err)
	}
	if c.Server.MaxConnections < 1 || c.Server.MaxConnections > 256 {
		bad("server.max_connections must be 1-256")
	}
	if c.Server.Name == "" || len(c.Server.Name) > 64 || strings.ContainsAny(c.Server.Name, " \t\r\n/") {
		bad("server.name must be a host name of at most 64 characters")
	}
	if len(c.Shares.Roots) == 0 {
		bad("shares.roots: at least one root is required")
	}
	for i, r := range c.Shares.Roots {
		if err := filesapi.ValidSharePath(r); err != nil {
			bad("shares.roots %q: %v", r, err)
			continue
		}
		for _, o := range c.Shares.Roots[i+1:] {
			if r == o || strings.HasPrefix(o, r+"/") || strings.HasPrefix(r, o+"/") {
				bad("shares.roots %q and %q overlap", r, o)
			}
		}
	}
	if sc := c.ShadowCopies; sc.Snapdir != "" || sc.Format != "" {
		if !sc.Enabled() {
			bad("shadow_copies: snapdir and format go together")
		}
		if path.IsAbs(sc.Snapdir) || strings.Contains(sc.Snapdir, "..") || strings.ContainsAny(sc.Snapdir, "\r\n\\\"") {
			bad("shadow_copies.snapdir must be relative to the share (e.g. .snapshots)")
		}
		if strings.ContainsAny(sc.Format, "\r\n\\\"") || len(sc.Format) > 128 {
			bad("shadow_copies.format must be one line")
		}
		if sc.Sort != "" && sc.Sort != "asc" && sc.Sort != "desc" {
			bad("shadow_copies.sort must be asc or desc")
		}
	}
	for name, p := range map[string]string{"net": c.Samba.Net, "sharesec": c.Samba.Sharesec, "samba_tool": c.Samba.SambaTool,
		"smbstatus": c.Samba.Smbstatus, "smbcontrol": c.Samba.Smbcontrol, "wbinfo": c.Samba.Wbinfo, "testparm": c.Samba.Testparm} {
		if !filepath.IsAbs(p) {
			bad("samba.%s must be an absolute path", name)
		}
	}
	if !filepath.IsAbs(c.State.Dir) || !filepath.IsAbs(c.State.SmbConf) {
		bad("state.dir and state.smb_conf must be absolute")
	}
	if c.Enrollment.TTL.Duration < time.Minute || c.Enrollment.TTL.Duration > 24*time.Hour {
		bad("enrollment.ttl must be 1m-24h")
	}
	if c.Enrollment.MaxFailures < 1 || c.Enrollment.MaxFailures > 20 {
		bad("enrollment.max_failures must be 1-20")
	}
	return errors.Join(errs...)
}
