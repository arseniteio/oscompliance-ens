// Package keys finds the private keys and certificates on disk under a set of roots: what they are, their
// fingerprint, who can read them and, for certificates, when they expire and with what algorithms.
package keys

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io/fs"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/arseniteio/oscompliance-ens/agent/internal/collect/wazuh"
	"github.com/arseniteio/oscompliance-ens/agent/internal/emit"
	"github.com/arseniteio/oscompliance-ens/agent/internal/fsread"
	"github.com/arseniteio/oscompliance-ens/catalog/fact"
)

type Config struct {
	Roots []string
	// Never walked: the system's public CAs, and trees too large to hold keys of the machine.
	Skip  []string
	Wazuh wazuh.AgentConfigPaths
}

var Default = Config{
	Roots: []string{"/etc", "/root", "/home", "/srv", "/opt", "/usr/local/etc", "/var/lib"},
	Skip:  []string{"/etc/ssl/certs", "/usr/share/ca-certificates", "/etc/pki/ca-trust", "/var/lib/docker", "/var/lib/containerd", "/var/lib/clamav", "/var/lib/apt", "/var/lib/dpkg"},
}

const (
	maxSize  = 64 << 10
	maxFiles = 2000
)

func Collect(e *emit.Emitter, cfg Config) error {

	roots := slices.Clone(cfg.Roots)
	// The key stores the manager declares are walked too, wherever they are.
	if paths, ok, err := wazuh.ReadSharedPaths(cfg.Wazuh); err == nil && ok {
		for _, p := range paths.KeyStores {
			if !slices.ContainsFunc(roots, func(r string) bool { return under(p, r) }) {
				roots = append(roots, p)
			}
		}
	}

	s := fact.KeySnapshot{Envelope: e.Envelope(fact.KeySnapshotFact), Status: fact.SourceRead, Roots: roots}
	files := 0

	for _, root := range roots {
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if d.IsDir() {
				if slices.ContainsFunc(cfg.Skip, func(x string) bool { return under(path, x) }) {
					return filepath.SkipDir
				}
				return nil
			}
			if !d.Type().IsRegular() {
				return nil
			}
			info, err := d.Info()
			if err != nil || info.Size() > maxSize || info.Size() == 0 {
				return nil
			}
			if files >= maxFiles {
				s.Truncated = true
				return filepath.SkipAll
			}
			data, err := fsread.ReadFile(path)
			if err != nil || !bytes.Contains(data, []byte("-----BEGIN ")) {
				return nil
			}
			files++
			for _, r := range records(e, path, data, info) {
				if err := e.Emit(r); err != nil {
					return err
				}
				switch r.(type) {
				case fact.KeyRecord:
					s.Keys++
				case fact.CertificateRecord:
					s.Certificates++
				}
			}
			return nil
		})
		if err != nil {
			s.Status, s.Error = fact.SourceError, err.Error()
			break
		}
	}

	return e.Emit(s)
}

func under(path, root string) bool {
	root = strings.TrimRight(root, "/")
	return path == root || strings.HasPrefix(path, root+"/")
}

// records reads every PEM block of a file: private keys and certificates.
func records(e *emit.Emitter, path string, data []byte, info fs.FileInfo) []any {

	var out []any
	mode := fmt.Sprintf("%04o", info.Mode().Perm())
	owner := ownerOf(info)

	for rest := data; ; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		switch {
		case strings.HasSuffix(block.Type, "PRIVATE KEY"):
			k := fact.KeyRecord{Envelope: e.Envelope(fact.KeyRecordFact), Path: path, Mode: mode, Owner: owner, Kind: kind(block.Type)}
			k.Fingerprint = fingerprint(path, block)
			out = append(out, k)
		case block.Type == "CERTIFICATE":
			if c, err := x509.ParseCertificate(block.Bytes); err == nil {
				out = append(out, certificate(e, path, c))
			}
		}
	}
	return out
}

func kind(blockType string) string {
	switch blockType {
	case "OPENSSH PRIVATE KEY":
		return "openssh"
	case "RSA PRIVATE KEY":
		return "rsa"
	case "EC PRIVATE KEY":
		return "ec"
	case "ENCRYPTED PRIVATE KEY":
		return "encrypted"
	}
	return "pkcs8"
}

// fingerprint is the SHA256 of the public part, written as OpenSSH writes it: for an OpenSSH key, of the
// blob of its .pub file; for a PEM key, of its public key in DER.
func fingerprint(path string, block *pem.Block) string {
	if block.Type == "OPENSSH PRIVATE KEY" {
		pub, err := fsread.ReadFile(path + ".pub")
		if err != nil {
			return ""
		}
		f := strings.Fields(string(pub))
		if len(f) < 2 {
			return ""
		}
		blob, err := base64.StdEncoding.DecodeString(f[1])
		if err != nil {
			return ""
		}
		sum := sha256.Sum256(blob)
		return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
	}

	var public any
	switch block.Type {
	case "RSA PRIVATE KEY":
		if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
			public = &k.PublicKey
		}
	case "EC PRIVATE KEY":
		if k, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
			public = &k.PublicKey
		}
	case "PRIVATE KEY":
		if k, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
			switch k := k.(type) {
			case *rsa.PrivateKey:
				public = &k.PublicKey
			case *ecdsa.PrivateKey:
				public = &k.PublicKey
			case ed25519.PrivateKey:
				public = k.Public()
			}
		}
	}
	if public == nil {
		return ""
	}
	der, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(der)
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
}

func certificate(e *emit.Emitter, path string, c *x509.Certificate) fact.CertificateRecord {
	r := fact.CertificateRecord{Envelope: e.Envelope(fact.CertificateRecordFact), Path: path, Subject: c.Subject.String(),
		NotAfter: c.NotAfter.UTC().Format(time.RFC3339), KeyAlgo: c.PublicKeyAlgorithm.String(), Signature: c.SignatureAlgorithm.String()}
	switch k := c.PublicKey.(type) {
	case *rsa.PublicKey:
		r.KeyBits = k.N.BitLen()
	case *ecdsa.PublicKey:
		r.KeyBits = k.Curve.Params().BitSize
	case ed25519.PublicKey:
		r.KeyBits = 256
	}
	return r
}

func ownerOf(info fs.FileInfo) string {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return ""
	}
	name := strconv.FormatUint(uint64(st.Uid), 10)
	if u, err := user.LookupId(name); err == nil {
		name = u.Username
	}
	group := strconv.FormatUint(uint64(st.Gid), 10)
	if g, err := user.LookupGroupId(group); err == nil {
		group = g.Name
	}
	return name + ":" + group
}
