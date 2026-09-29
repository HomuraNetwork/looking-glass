package enroll

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
)

type identityFile struct {
	PublicKey            string `json:"public_key"`
	PrivateKey           string `json:"private_key"`
	EncryptionPublicKey  string `json:"encryption_public_key,omitempty"`
	EncryptionPrivateKey string `json:"encryption_private_key,omitempty"`
}

func loadOrCreateIdentity(dataDir string) (identityFile, error) {
	path := filepath.Join(dataDir, "agent-identity.json")
	if b, err := os.ReadFile(path); err == nil {
		var existing identityFile
		if err := json.Unmarshal(b, &existing); err != nil {
			return identityFile{}, err
		}
		if existing.EncryptionPublicKey != "" && existing.EncryptionPrivateKey != "" {
			return existing, nil
		}
		if err := ensureEncryptionKey(&existing); err != nil {
			return identityFile{}, err
		}
		if err := writeIdentity(path, existing); err != nil {
			return identityFile{}, err
		}
		return existing, nil
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return identityFile{}, err
	}
	identity := identityFile{
		PublicKey:  base64.RawURLEncoding.EncodeToString(pub),
		PrivateKey: base64.RawURLEncoding.EncodeToString(priv),
	}
	if err := ensureEncryptionKey(&identity); err != nil {
		return identityFile{}, err
	}
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return identityFile{}, err
	}
	if err := writeIdentity(path, identity); err != nil {
		return identityFile{}, err
	}
	return identity, nil
}

func ensureEncryptionKey(identity *identityFile) error {
	priv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	identity.EncryptionPrivateKey = base64.RawURLEncoding.EncodeToString(priv.Bytes())
	identity.EncryptionPublicKey = base64.RawURLEncoding.EncodeToString(priv.PublicKey().Bytes())
	return nil
}

func writeIdentity(path string, identity identityFile) error {
	b, err := json.MarshalIndent(identity, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		return err
	}
	return nil
}
