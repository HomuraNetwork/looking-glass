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

	"hlg/internal/config"
)

func TestApplyBundleWritesUsableCertificatePair(t *testing.T) {
	certPEM, keyPEM := testCertificatePEM(t, "edge01.example.net")
	store := New(t.TempDir())
	certPath, keyPath, err := store.ApplyBundle(config.CertificateBundle{
		NodeID:        "edge01",
		Domain:        "edge01.example.net",
		CertExpiresAt: time.Now().Add(time.Hour).Unix(),
		CertPEM:       certPEM,
		KeyPEM:        keyPEM,
	})
	if err != nil {
		t.Fatal(err)
	}
	if certPath != filepath.Join(store.DataDir, CertFile) || keyPath != filepath.Join(store.DataDir, KeyFile) {
		t.Fatalf("paths = %s %s", certPath, keyPath)
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

func TestApplyBundleRejectsMismatchedKeyPair(t *testing.T) {
	certPEM, _ := testCertificatePEM(t, "edge01.example.net")
	_, otherKeyPEM := testCertificatePEM(t, "edge02.example.net")
	_, _, err := New(t.TempDir()).ApplyBundle(config.CertificateBundle{
		CertPEM: certPEM,
		KeyPEM:  otherKeyPEM,
	})
	if err == nil {
		t.Fatal("expected key pair error")
	}
}

func testCertificatePEM(t *testing.T, domain string) (string, string) {
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
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certOut := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyOut := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	return string(certOut), string(keyOut)
}
