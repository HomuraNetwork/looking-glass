package certstore

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	CertFile = "tls.crt"
	KeyFile  = "tls.key"
	// SourceFile records where the current serving certificate came from:
	// "managed" (a real certificate applied from the controller) or
	// "self-signed" (the bootstrap fallback). It lets startup prefer a cached
	// managed certificate and lets sync know whether a valid managed cert is
	// already in place.
	SourceFile = "tls.source"

	CertSourceManaged    = "managed"
	CertSourceSelfSigned = "self-signed"

	// selfSignedCertLifetime is the validity window for generated self-signed
	// certificates. Long enough to survive controller downtime; still bounded.
	selfSignedCertLifetime = 30 * 24 * time.Hour

	// selfSignedRegenThreshold regenerates certs whose remaining validity has
	// dropped below this window, so a long-running agent never serves an
	// expired certificate.
	selfSignedRegenThreshold = 48 * time.Hour
)

// certExpiry parses NotAfter from the first CERTIFICATE PEM block.
func certExpiry(certPath string) (time.Time, error) {
	body, err := os.ReadFile(certPath)
	if err != nil {
		return time.Time{}, err
	}
	block, _ := pem.Decode(body)
	if block == nil || block.Type != "CERTIFICATE" {
		return time.Time{}, fmt.Errorf("%s: no certificate PEM block", certPath)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return time.Time{}, fmt.Errorf("%s: parse certificate: %w", certPath, err)
	}
	return cert.NotAfter, nil
}

// keyPairValid reports whether the on-disk certificate and key load as a
// matching pair. Each write is atomic (temp+rename), but a crash between the
// cert and key writes can still leave a mismatched pair; validating on reuse
// lets such a state self-heal instead of serving a broken TLS handshake.
func keyPairValid(certPath, keyPath string) bool {
	_, err := tls.LoadX509KeyPair(certPath, keyPath)
	return err == nil
}

func (s Store) EnsureSelfSigned(domain string) (string, string, error) {
	if err := os.MkdirAll(s.DataDir, 0o700); err != nil {
		return "", "", err
	}
	certPath := filepath.Join(s.DataDir, CertFile)
	keyPath := filepath.Join(s.DataDir, KeyFile)
	if _, certErr := os.Stat(certPath); certErr == nil {
		if _, keyErr := os.Stat(keyPath); keyErr == nil {
			// Reuse the existing pair only while it stays comfortably valid and
			// only when it is actually a self-signed fallback: a managed
			// certificate must never be overwritten here. A mismatched pair
			// (from a crash between the cert and key writes) is regenerated.
			if source, _ := s.ReadSource(); source != CertSourceManaged {
				if expiry, parseErr := certExpiry(certPath); parseErr == nil && expiry.After(time.Now().Add(selfSignedRegenThreshold)) && keyPairValid(certPath, keyPath) {
					return certPath, keyPath, nil
				}
			} else {
				return certPath, keyPath, nil
			}
		}
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return "", "", err
	}
	template := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: domain,
		},
		DNSNames:              []string{domain, "localhost"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(selfSignedCertLifetime),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return "", "", err
	}
	certOut := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", "", err
	}
	keyOut := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	// Write both halves through temp files and rename them into place, so a
	// crash between the two writes cannot leave a certificate paired with a
	// mismatched key (which fails every TLS handshake).
	if err := s.WriteSource(CertSourceSelfSigned); err != nil {
		return "", "", err
	}
	if err := writeReplace(certPath, certOut, 0o600); err != nil {
		return "", "", err
	}
	if err := writeReplace(keyPath, keyOut, 0o600); err != nil {
		return "", "", err
	}
	return certPath, keyPath, nil
}

// ReadSource reports where the current serving certificate came from. A missing
// marker is treated as self-signed.
func (s Store) ReadSource() (string, error) {
	body, err := os.ReadFile(filepath.Join(s.DataDir, SourceFile))
	if err != nil {
		return CertSourceSelfSigned, err
	}
	source := strings.TrimSpace(string(body))
	if source == CertSourceManaged {
		return CertSourceManaged, nil
	}
	return CertSourceSelfSigned, nil
}

// WriteSource records the provenance of the current serving certificate.
func (s Store) WriteSource(source string) error {
	if err := os.MkdirAll(s.DataDir, 0o700); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(s.DataDir, SourceFile), []byte(source+"\n"), 0o600)
}

// HasManagedCertificate reports whether a cached managed certificate exists and
// has not yet expired. Startup uses it to serve immediately from cache instead
// of falling back to a self-signed certificate.
func (s Store) HasManagedCertificate() (bool, time.Time) {
	source, _ := s.ReadSource()
	if source != CertSourceManaged {
		return false, time.Time{}
	}
	certPath := filepath.Join(s.DataDir, CertFile)
	keyPath := filepath.Join(s.DataDir, KeyFile)
	expiry, err := certExpiry(certPath)
	if err != nil {
		return false, time.Time{}
	}
	if !expiry.After(time.Now()) {
		return false, expiry
	}
	// A managed marker with a mismatched/missing key would fail every TLS
	// handshake; treat it as unusable so startup regenerates a self-signed pair.
	if !keyPairValid(certPath, keyPath) {
		return false, time.Time{}
	}
	return true, expiry
}
