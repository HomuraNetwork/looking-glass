// Package initstring parses the controller-issued one-line init string: the
// controller and the one-time init key in a single value, so a container or
// host only needs LG_INIT_STRING instead of LG_CONTROLLER + LG_INIT_TOKEN.
//
// Two forms are accepted:
//
//	compact: [http://|https://]host[:port]/lginit_<key>
//	encoded: hlginit1.<base64url(JSON{"v":1,"controller":"...","key":"..."})>
//
// The compact form is the friendly one the controller and panel emit: the
// scheme may be omitted (https is assumed) and the port is included only when
// non-default. The encoded form is kept for compatibility.
//
// The node domain and node id are deliberately NOT part of either form: they
// are authoritative in the controller's signed config bundle.
package initstring

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"regexp"
	"strings"
)

// Prefix identifies an encoded init string (the legacy/UI form).
const Prefix = "hlginit1."

// KeyPrefix is the fixed prefix of a one-time init key.
const KeyPrefix = "lginit_"

// Payload is the decoded init string.
type Payload struct {
	V          int    `json:"v"`
	Controller string `json:"controller"`
	Key        string `json:"key"`
}

// IsInitString reports whether value is the encoded (non-compact) form.
func IsInitString(value string) bool {
	return strings.HasPrefix(strings.TrimSpace(value), Prefix)
}

// LooksLikeInitKey reports whether key has the shape of a one-time init key
// (`lginit_` + base64url). It never contacts the controller; a well-formed key
// can still be expired or already consumed.
func LooksLikeInitKey(key string) bool {
	if !strings.HasPrefix(key, KeyPrefix) {
		return false
	}
	rest := strings.TrimPrefix(key, KeyPrefix)
	if len(rest) < 20 || len(rest) > 128 {
		return false
	}
	for _, r := range rest {
		if !isBase64URL(r) {
			return false
		}
	}
	return true
}

// Parse decodes and validates an init string, failing closed.
func Parse(value string) (Payload, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return Payload{}, fmt.Errorf("init string: empty")
	}
	if IsInitString(trimmed) {
		return parseEncoded(trimmed)
	}
	return parseCompact(trimmed)
}

func parseEncoded(value string) (Payload, error) {
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(value, Prefix))
	if err != nil {
		return Payload{}, fmt.Errorf("init string: invalid base64url: %w", err)
	}
	var payload Payload
	if err := json.Unmarshal(raw, &payload); err != nil {
		return Payload{}, fmt.Errorf("init string: invalid JSON: %w", err)
	}
	if payload.V != 1 {
		return Payload{}, fmt.Errorf("init string: unsupported version %d", payload.V)
	}
	if err := validateController(payload.Controller); err != nil {
		return Payload{}, err
	}
	if !LooksLikeInitKey(payload.Key) {
		return Payload{}, fmt.Errorf("init string: invalid init key")
	}
	return payload, nil
}

// parseCompact accepts "[scheme://]host[:port]/lginit_<key>". The remainder
// after the last "/" is the key, so the authority cannot contain a path.
func parseCompact(value string) (Payload, error) {
	slash := strings.LastIndex(value, "/")
	if slash < 0 {
		return Payload{}, fmt.Errorf("init string: expected [scheme://]host[:port]/%s<key>", KeyPrefix)
	}
	key := value[slash+1:]
	authority := value[:slash]
	if !LooksLikeInitKey(key) {
		return Payload{}, fmt.Errorf("init string: invalid init key")
	}
	if authority == "" {
		return Payload{}, fmt.Errorf("init string: missing controller host")
	}

	scheme := "https"
	if index := strings.Index(authority, "://"); index >= 0 {
		scheme = strings.ToLower(authority[:index])
		authority = authority[index+3:]
		if scheme != "http" && scheme != "https" {
			return Payload{}, fmt.Errorf("init string: scheme must be http or https")
		}
	}
	if authority == "" || strings.ContainsAny(authority, "/?#") {
		return Payload{}, fmt.Errorf("init string: invalid controller host")
	}
	if err := validateHostPort(authority); err != nil {
		return Payload{}, err
	}
	return Payload{V: 1, Controller: scheme + "://" + authority, Key: key}, nil
}

func validateController(controller string) error {
	lower := strings.ToLower(controller)
	var authority string
	switch {
	case strings.HasPrefix(lower, "https://"):
		authority = controller[len("https://"):]
	case strings.HasPrefix(lower, "http://"):
		authority = controller[len("http://"):]
	default:
		return fmt.Errorf("init string: controller must be an http(s) URL")
	}
	if authority == "" || strings.ContainsAny(authority, "/?#") {
		return fmt.Errorf("init string: invalid controller URL")
	}
	return validateHostPort(authority)
}

var hostnameLabel = regexp.MustCompile(`^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$`)

// validateHostPort validates "host", "host:port", "[v6]", or "[v6]:port".
func validateHostPort(hostport string) error {
	host := hostport
	port := ""
	if strings.HasPrefix(hostport, "[") {
		end := strings.Index(hostport, "]")
		if end < 0 {
			return fmt.Errorf("init string: unterminated IPv6 address")
		}
		host = hostport[1:end]
		rest := hostport[end+1:]
		if rest != "" {
			if !strings.HasPrefix(rest, ":") {
				return fmt.Errorf("init string: invalid host")
			}
			port = rest[1:]
		}
	} else if strings.Count(hostport, ":") == 1 {
		host, port, _ = strings.Cut(hostport, ":")
	} else if strings.Contains(hostport, ":") {
		return fmt.Errorf("init string: IPv6 addresses must be bracketed")
	}
	if host == "" {
		return fmt.Errorf("init string: missing controller host")
	}
	if net.ParseIP(host) == nil {
		for _, label := range strings.Split(host, ".") {
			if !hostnameLabel.MatchString(label) {
				return fmt.Errorf("init string: invalid controller host")
			}
		}
	}
	if port != "" {
		value, err := net.LookupPort("tcp", port)
		if err != nil || value <= 0 || value > 65535 {
			return fmt.Errorf("init string: invalid port")
		}
	}
	return nil
}

func isBase64URL(r rune) bool {
	return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_'
}
