package config

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"
)

var (
	ErrCertBundleSignature = errors.New("certificate bundle signature invalid")
	ErrCertBundleWrongNode = errors.New("certificate bundle node mismatch")
	ErrCertBundleExpired   = errors.New("certificate bundle expired")
	ErrCertBundleNotYet    = errors.New("certificate bundle not yet valid")
	ErrCertBundleConfigKID = errors.New("certificate bundle config_kid mismatch")
)

func CertificateBundleSigningPayload(bundle CertificateBundle) ([]byte, error) {
	bundle.Signature = ""
	return json.Marshal(bundle)
}

func VerifySignedCertificateBundle(bundle CertificateBundle, configBundle SignedBundle, nodeID string, now time.Time) error {
	if bundle.NodeID != nodeID || bundle.NodeID != configBundle.NodeID || bundle.Domain != configBundle.Domain {
		return ErrCertBundleWrongNode
	}
	if bundle.IssuedAt > now.Add(signedBundleClockSkew).Unix() {
		return ErrCertBundleNotYet
	}
	if bundle.CertExpiresAt <= now.Unix() {
		return ErrCertBundleExpired
	}
	if bundle.ConfigKID == "" || bundle.ConfigKID != configBundle.ConfigKID {
		return ErrCertBundleConfigKID
	}
	publicKey, err := bundleConfigPublicKey(configBundle)
	if err != nil {
		return err
	}
	signature, err := base64.RawURLEncoding.DecodeString(bundle.Signature)
	if err != nil {
		return ErrCertBundleSignature
	}
	payload, err := CertificateBundleSigningPayload(bundle)
	if err != nil {
		return err
	}
	if !ed25519.Verify(publicKey, payload, signature) {
		return ErrCertBundleSignature
	}
	return nil
}
