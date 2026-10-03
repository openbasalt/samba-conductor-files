package filesapi

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Identity is a TLS key pair and its pin. Keys are ECDSA P-256 with a
// self-signed certificate: trust comes from the pin, never from a CA, so the
// certificate's validity dates are not what makes it trusted (a key stays
// pinned until it is revoked or replaced by a new enrollment).
type Identity struct {
	Cert tls.Certificate
	Pin  string
}

// File names of an identity inside its directory.
const (
	KeyFile  = "tls-key.pem"
	CertFile = "tls-cert.pem"
)

// pinPrefix marks the hash function of a pin.
const pinPrefix = "sha256:"

// PinOf returns the pin of a certificate: "sha256:" + base64url (no
// padding) of the SHA-256 of its SubjectPublicKeyInfo.
func PinOf(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return pinPrefix + base64.RawURLEncoding.EncodeToString(sum[:])
}

var pinRE = regexp.MustCompile(`^sha256:[A-Za-z0-9_-]{43}$`)

// ValidPin reports whether p has the shape of a pin.
func ValidPin(p string) bool { return pinRE.MatchString(p) }

// PinEqual compares two pins in constant time.
func PinEqual(a, b string) bool { return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1 }

// LoadOrCreateIdentity loads the key pair in dir, generating it on first
// use. dir must exist, belong to the current user and be private (no
// group or other permissions): it holds a private key.
func LoadOrCreateIdentity(dir, commonName string) (Identity, error) {
	st, err := os.Stat(dir)
	if err != nil {
		return Identity{}, err
	}
	if !st.IsDir() || st.Mode().Perm()&0o077 != 0 {
		return Identity{}, fmt.Errorf("filesapi: %s must be a directory with mode 0700", dir)
	}
	keyPath, certPath := filepath.Join(dir, KeyFile), filepath.Join(dir, CertFile)
	if _, err := os.Stat(keyPath); errors.Is(err, os.ErrNotExist) {
		if err := generate(keyPath, certPath, commonName); err != nil {
			return Identity{}, err
		}
	}
	return LoadIdentity(keyPath, certPath)
}

// LoadIdentity reads a key pair (the key file must not be readable by
// group or others).
func LoadIdentity(keyPath, certPath string) (Identity, error) {
	st, err := os.Stat(keyPath)
	if err != nil {
		return Identity{}, err
	}
	if st.Mode().Perm()&0o077 != 0 {
		return Identity{}, fmt.Errorf("filesapi: %s must not be readable by group or others", keyPath)
	}
	c, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return Identity{}, err
	}
	leaf, err := x509.ParseCertificate(c.Certificate[0])
	if err != nil {
		return Identity{}, err
	}
	c.Leaf = leaf
	return Identity{Cert: c, Pin: PinOf(leaf)}, nil
}

func generate(keyPath, certPath, cn string) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return err
	}
	if cn == "" || len(cn) > 64 {
		cn = "conductor-files"
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.AddDate(20, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	if err := writeExclusive(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})); err != nil {
		return err
	}
	if err := writeExclusive(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})); err != nil {
		_ = os.Remove(keyPath)
		return err
	}
	return nil
}

func writeExclusive(p string, b []byte) error {
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// peerPin returns the pin of the single certificate a peer presented.
func peerPin(certs []*x509.Certificate) (string, error) {
	if len(certs) == 0 {
		return "", errors.New("no certificate presented")
	}
	return PinOf(certs[0]), nil
}

// ClientConfig is the TLS configuration conductor uses towards an agent
// whose key is pinned as agentPin.
func ClientConfig(id Identity, agentPin, serverName string) *tls.Config {
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{id.Cert},
		ServerName:   serverName,
		// No CA: the agent's key is pinned (VerifyConnection).
		InsecureSkipVerify: true, //nolint:gosec // the pin replaces chain verification
		VerifyConnection: func(cs tls.ConnectionState) error {
			got, err := peerPin(cs.PeerCertificates)
			if err != nil {
				return err
			}
			if !PinEqual(got, agentPin) {
				return &PinMismatchError{Want: agentPin, Got: got}
			}
			return nil
		},
	}
}

// PinMismatchError is returned when a peer presents another key than the
// pinned one.
type PinMismatchError struct{ Want, Got string }

func (e *PinMismatchError) Error() string {
	return fmt.Sprintf("filesapi: the peer's key %s is not the pinned key %s", e.Got, e.Want)
}

// DefaultTimeout bounds one call when the context has no deadline.
const DefaultTimeout = 90 * time.Second

// Call sends one request to the agent at addr (host:port), pinning its key,
// and returns its response.
func Call(ctx context.Context, addr string, id Identity, agentPin string, req Request) (Response, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return Response{}, err
	}
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, DefaultTimeout)
		defer cancel()
	}
	d := tls.Dialer{NetDialer: &net.Dialer{Timeout: 10 * time.Second}, Config: ClientConfig(id, agentPin, host)}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return Response{}, err
	}
	defer func() { _ = conn.Close() }()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	if err := WriteMessage(conn, req); err != nil {
		return Response{}, err
	}
	var resp Response
	if err := ReadMessage(bufio.NewReaderSize(conn, 64<<10), &resp); err != nil {
		return Response{}, fmt.Errorf("filesapi: reading the response: %w", err)
	}
	if resp.ID != req.ID {
		return Response{}, errors.New("filesapi: response for another request")
	}
	return resp, nil
}

// ---- enrollment codes ----

// codePrefix versions the enrollment code format.
const codePrefix = "cfe1"

// FormatEnrollmentCode renders the code an administrator copies from the
// file server into conductor: the one-time token and the agent's pin.
func FormatEnrollmentCode(token, agentPin string) string {
	return codePrefix + "." + token + "." + strings.TrimPrefix(agentPin, pinPrefix)
}

// ParseEnrollmentCode splits a code into token and agent pin.
func ParseEnrollmentCode(code string) (token, agentPin string, err error) {
	parts := strings.Split(strings.TrimSpace(code), ".")
	if len(parts) != 3 || parts[0] != codePrefix || !tokenRE.MatchString(parts[1]) || !ValidPin(pinPrefix+parts[2]) {
		return "", "", errors.New("filesapi: not an enrollment code (cfe1.<token>.<key>)")
	}
	return parts[1], pinPrefix + parts[2], nil
}

// NewToken returns a random one-time token (32 bytes, base64url).
func NewToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// TokenHash is what the agent stores of a token.
func TokenHash(token string) string {
	sum := sha256.Sum256([]byte("conductor-files enrollment\x00" + token))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

var hostRE = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,62}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,62}[A-Za-z0-9])?)*$`)

// NormalizeAddress checks an agent address ("host" or "host:port", the host
// a DNS name or an IP address) and returns host:port (DefaultPort when
// omitted).
func NormalizeAddress(addr string) (string, error) {
	addr = strings.TrimSpace(addr)
	if addr == "" || len(addr) > 260 {
		return "", errors.New("filesapi: address required")
	}
	host, port := addr, strconv.Itoa(DefaultPort)
	if h, p, err := net.SplitHostPort(addr); err == nil {
		host, port = h, p
	} else if strings.Count(addr, ":") > 1 {
		// A bare IPv6 address.
		host = strings.Trim(addr, "[]")
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return "", errors.New("filesapi: invalid port")
	}
	if ip := net.ParseIP(host); ip == nil && (!hostRE.MatchString(host) || len(host) > 253) {
		return "", errors.New("filesapi: invalid host name")
	}
	return net.JoinHostPort(host, strconv.Itoa(n)), nil
}
