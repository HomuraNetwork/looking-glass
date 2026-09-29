package certstore

import (
	"crypto/tls"
	"os"
	"path/filepath"

	"hlg/internal/config"
)

type Store struct {
	DataDir string
}

func New(dataDir string) Store {
	return Store{DataDir: dataDir}
}

func (s Store) ApplyBundle(bundle config.CertificateBundle) (string, string, error) {
	if err := os.MkdirAll(s.DataDir, 0o700); err != nil {
		return "", "", err
	}
	certPEM := bundle.CertPEM
	if bundle.CAPEM != "" {
		certPEM += bundle.CAPEM
	}
	if _, err := tls.X509KeyPair([]byte(certPEM), []byte(bundle.KeyPEM)); err != nil {
		return "", "", err
	}
	certPath := filepath.Join(s.DataDir, CertFile)
	keyPath := filepath.Join(s.DataDir, KeyFile)
	if err := writeReplace(certPath, []byte(certPEM), 0o600); err != nil {
		return "", "", err
	}
	if err := writeReplace(keyPath, []byte(bundle.KeyPEM), 0o600); err != nil {
		return "", "", err
	}
	if err := s.WriteSource(CertSourceManaged); err != nil {
		return "", "", err
	}
	return certPath, keyPath, nil
}

func writeReplace(path string, data []byte, perm os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, perm); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return os.Chmod(path, perm)
}
