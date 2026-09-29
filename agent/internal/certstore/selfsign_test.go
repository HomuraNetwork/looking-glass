package certstore

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writeSelfSignedPair writes a self-signed pair with the requested lifetime
// and returns its NotAfter.
func writeSelfSignedPair(t *testing.T, dir string, domain string, lifetime time.Duration) time.Time {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}
	template := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: domain,
		},
		DNSNames:              []string{domain},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(lifetime),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPath := filepath.Join(dir, CertFile)
	keyPath := filepath.Join(dir, KeyFile)
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}), 0o600); err != nil {
		t.Fatal(err)
	}
	return template.NotAfter
}

func TestEnsureSelfSignedGeneratesWhenMissing(t *testing.T) {
	store := New(t.TempDir())
	certPath, keyPath, err := store.EnsureSelfSigned("edge01.example.net")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tls.LoadX509KeyPair(certPath, keyPath); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("key mode = %v", info.Mode().Perm())
	}
}

func TestEnsureSelfSignedKeepsFreshCertificate(t *testing.T) {
	dir := t.TempDir()
	notAfter := writeSelfSignedPair(t, dir, "edge01.example.net", 7*24*time.Hour)
	store := New(dir)
	certPath, keyPath, err := store.EnsureSelfSigned("edge01.example.net")
	if err != nil {
		t.Fatal(err)
	}
	if certPath != filepath.Join(dir, CertFile) || keyPath != filepath.Join(dir, KeyFile) {
		t.Fatalf("paths = %s %s", certPath, keyPath)
	}
	body, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(body)
	if block == nil {
		t.Fatal("no PEM block")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if delta := cert.NotAfter.Sub(notAfter); delta < -2*time.Second || delta > 2*time.Second {
		t.Fatalf("fresh cert was regenerated: NotAfter %v, want %v", cert.NotAfter, notAfter)
	}
}

func TestEnsureSelfSignedRegeneratesExpiredCertificate(t *testing.T) {
	dir := t.TempDir()
	writeSelfSignedPair(t, dir, "edge01.example.net", -time.Hour)
	store := New(dir)
	certPath, keyPath, err := store.EnsureSelfSigned("edge01.example.net")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tls.LoadX509KeyPair(certPath, keyPath); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(body)
	if block == nil {
		t.Fatal("no PEM block")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if !cert.NotAfter.After(time.Now()) {
		t.Fatalf("expired cert was not regenerated: NotAfter %v", cert.NotAfter)
	}
	if cert.NotAfter.Before(time.Now().Add(selfSignedCertLifetime - time.Hour)) {
		t.Fatalf("regenerated cert lifetime too short: NotAfter %v", cert.NotAfter)
	}
}

func TestEnsureSelfSignedRegeneratesMalformedCertificate(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, CertFile), []byte("not a pem file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	keyOut := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if err := os.WriteFile(filepath.Join(dir, KeyFile), keyOut, 0o600); err != nil {
		t.Fatal(err)
	}
	store := New(dir)
	certPath, keyPath, err := store.EnsureSelfSigned("edge01.example.net")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tls.LoadX509KeyPair(certPath, keyPath); err != nil {
		t.Fatalf("malformed cert was not regenerated: %v", err)
	}
	if _, err := certExpiry(certPath); err != nil {
		t.Fatalf("regenerated cert does not parse: %v", err)
	}
}

func TestEnsureSelfSignedRegeneratesMismatchedPair(t *testing.T) {
	dir := t.TempDir()
	// A fresh, long-lived self-signed certificate, then its key replaced by a
	// DIFFERENT pair's key: the state a crash between the cert and key writes
	// can leave behind. Only the mismatch can trigger regeneration here, since
	// the certificate is well within its validity.
	writeSelfSignedPair(t, dir, "edge01.example.net", 30*24*time.Hour)
	otherDir := t.TempDir()
	writeSelfSignedPair(t, otherDir, "edge01.example.net", 30*24*time.Hour)
	otherKey, err := os.ReadFile(filepath.Join(otherDir, KeyFile))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, KeyFile), otherKey, 0o600); err != nil {
		t.Fatal(err)
	}

	store := New(dir)
	certPath, keyPath, err := store.EnsureSelfSigned("edge01.example.net")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tls.LoadX509KeyPair(certPath, keyPath); err != nil {
		t.Fatalf("mismatched pair was not regenerated: %v", err)
	}
}

func TestHasManagedCertificateRejectsMismatchedPair(t *testing.T) {
	dir := t.TempDir()
	writeSelfSignedPair(t, dir, "edge01.example.net", 30*24*time.Hour)
	otherDir := t.TempDir()
	writeSelfSignedPair(t, otherDir, "edge01.example.net", 30*24*time.Hour)
	otherKey, err := os.ReadFile(filepath.Join(otherDir, KeyFile))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, KeyFile), otherKey, 0o600); err != nil {
		t.Fatal(err)
	}
	store := New(dir)
	if err := store.WriteSource(CertSourceManaged); err != nil {
		t.Fatal(err)
	}
	// Managed marker but an unusable pair: startup must not consider it good.
	if ok, _ := store.HasManagedCertificate(); ok {
		t.Fatal("a mismatched managed pair must not be reported as usable")
	}
}

func TestEnsureSelfSignedUsesECDSA(t *testing.T) {
	store := New(t.TempDir())
	certPath, keyPath, err := store.EnsureSelfSigned("edge01.example.net")
	if err != nil {
		t.Fatal(err)
	}
	keyBody, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(keyBody)
	if block == nil {
		t.Fatal("no key PEM block")
	}
	if _, err := x509.ParsePKCS8PrivateKey(block.Bytes); err != nil {
		t.Fatalf("expected PKCS8 (ECDSA) key, got: %v", err)
	}
	if _, err := tls.LoadX509KeyPair(certPath, keyPath); err != nil {
		t.Fatal(err)
	}
	// A freshly generated pair records its provenance as self-signed.
	source, err := store.ReadSource()
	if err != nil || source != CertSourceSelfSigned {
		t.Fatalf("source = %q err=%v", source, err)
	}
}

func TestEnsureSelfSignedNeverOverwritesManagedCertificate(t *testing.T) {
	dir := t.TempDir()
	writeSelfSignedPair(t, dir, "edge01.example.net", 7*24*time.Hour)
	store := New(dir)
	if err := store.WriteSource(CertSourceManaged); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Join(dir, CertFile))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.EnsureSelfSigned("edge01.example.net"); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(filepath.Join(dir, CertFile))
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("EnsureSelfSigned overwrote a managed certificate")
	}
	if source, _ := store.ReadSource(); source != CertSourceManaged {
		t.Fatalf("source = %q, want managed", source)
	}
}

func TestHasManagedCertificate(t *testing.T) {
	dir := t.TempDir()
	store := New(dir)

	// No files at all.
	if ok, _ := store.HasManagedCertificate(); ok {
		t.Fatal("expected no managed certificate when none exists")
	}

	// A self-signed pair is not a managed certificate.
	if _, _, err := store.EnsureSelfSigned("edge01.example.net"); err != nil {
		t.Fatal(err)
	}
	if ok, _ := store.HasManagedCertificate(); ok {
		t.Fatal("self-signed must not count as managed")
	}

	// Mark it managed and still valid -> true with expiry.
	if err := store.WriteSource(CertSourceManaged); err != nil {
		t.Fatal(err)
	}
	ok, expiry := store.HasManagedCertificate()
	if !ok || expiry.IsZero() {
		t.Fatalf("expected managed certificate, got ok=%v expiry=%v", ok, expiry)
	}

	// Mark managed but expired -> false.
	writeSelfSignedPair(t, dir, "edge01.example.net", -time.Hour)
	if err := store.WriteSource(CertSourceManaged); err != nil {
		t.Fatal(err)
	}
	if ok, _ := store.HasManagedCertificate(); ok {
		t.Fatal("expired managed certificate must not count")
	}
}
