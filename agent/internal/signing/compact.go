package signing

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
)

var (
	ErrMalformedCompact = errors.New("malformed compact token")
)

func SignCompact(payload any, privateKey ed25519.PrivateKey) (string, error) {
	encodedPayload, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	signature := ed25519.Sign(privateKey, encodedPayload)
	return base64.RawURLEncoding.EncodeToString(encodedPayload) + "." +
		base64.RawURLEncoding.EncodeToString(signature), nil
}

func SplitCompact(raw string) ([]byte, []byte, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return nil, nil, ErrMalformedCompact
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, nil, ErrMalformedCompact
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, nil, ErrMalformedCompact
	}
	return payload, signature, nil
}
