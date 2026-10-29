package keys

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"path/filepath"
	"testing"
	"time"

	"github.com/OpenSourceCompliance/oscompliance-ens/agent/internal/collect/collecttest"
	"github.com/OpenSourceCompliance/oscompliance-ens/agent/internal/emit"
)

func TestCollect(t *testing.T) {

	dir := t.TempDir()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalECPrivateKey(key)
	collecttest.WriteFile(t, filepath.Join(dir, "srv", "tls", "server.key"), string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})), 0o644)

	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "web01"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)}
	cert, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	collecttest.Write(t, filepath.Join(dir, "srv", "tls", "server.crt"), string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert})))
	collecttest.Write(t, filepath.Join(dir, "srv", "skip", "ca.crt"), string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert})))
	collecttest.Write(t, filepath.Join(dir, "srv", "notes.txt"), "nothing here")

	facts := collecttest.Facts(t, func(e *emit.Emitter) error {
		return Collect(e, Config{Roots: []string{filepath.Join(dir, "srv")}, Skip: []string{filepath.Join(dir, "srv", "skip")}})
	})

	var keys, certs int
	for _, f := range facts {
		switch f["fact"] {
		case "key_record":
			keys++
			if f["mode"] != "0644" || f["key_kind"] != "ec" || len(f["fingerprint"].(string)) < 20 {
				t.Errorf("key: %v", f)
			}
		case "certificate_record":
			certs++
			if f["not_after"] != "2027-01-01T00:00:00Z" || f["key_algorithm"] != "ECDSA" || f["key_bits"] != 256.0 {
				t.Errorf("certificate: %v", f)
			}
		case "key_snapshot":
			if f["keys_emitted"] != 1.0 || f["certificates_emitted"] != 1.0 {
				t.Errorf("snapshot: %v", f)
			}
		}
	}
	if keys != 1 || certs != 1 {
		t.Errorf("keys %d certificates %d", keys, certs)
	}
}
