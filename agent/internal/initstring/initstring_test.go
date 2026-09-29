package initstring

import (
	"encoding/base64"
	"testing"
)

const testKey = "lginit_8PVlu4Av1d_J8h5Ri06dAon4t8KK_izFqW-nGXQqNC8"

func encodeLegacy(payload string) string {
	return Prefix + base64.RawURLEncoding.EncodeToString([]byte(payload))
}

func TestParseCompact(t *testing.T) {
	cases := map[string]string{
		"lg.example.com/" + testKey:          "https://lg.example.com",
		"lg.example.com:8443/" + testKey:     "https://lg.example.com:8443",
		"http://lg-worker:8787/" + testKey:   "http://lg-worker:8787",
		"https://lg.example.com/" + testKey:  "https://lg.example.com",
		"[2001:db8::1]:8443/" + testKey:      "https://[2001:db8::1]:8443",
		"  lg.example.com/" + testKey + "  ": "https://lg.example.com",
	}
	for value, controller := range cases {
		payload, err := Parse(value)
		if err != nil {
			t.Errorf("Parse(%q): %v", value, err)
			continue
		}
		if payload.Controller != controller || payload.Key != testKey || payload.V != 1 {
			t.Errorf("Parse(%q) = %+v", value, payload)
		}
	}
}

func TestParseEncodedLegacy(t *testing.T) {
	encoded := encodeLegacy(`{"v":1,"controller":"https://lg.example","key":"` + testKey + `"}`)
	payload, err := Parse(encoded)
	if err != nil {
		t.Fatalf("Parse(encoded): %v", err)
	}
	if payload.Controller != "https://lg.example" || payload.Key != testKey {
		t.Fatalf("unexpected payload: %+v", payload)
	}
}

func TestParseRejectsInvalid(t *testing.T) {
	badVersion := encodeLegacy(`{"v":2,"controller":"https://lg.example","key":"` + testKey + `"}`)
	badJSON := encodeLegacy(`{"v":1,`)
	cases := map[string]string{
		"empty":              "",
		"no separator":       "lg.example.com",
		"short key":          "lg.example.com/lginit_abc",
		"wrong key prefix":   "lg.example.com/lgnode_8PVlu4Av1d_J8h5Ri06dAon4t8KK_izF",
		"bad key charset":    "lg.example.com/lginit_8PVlu4Av1d!J8h5Ri06dAon4t8KK_izF",
		"bad scheme":         "ftp://lg.example.com/" + testKey,
		"bad port":           "lg.example.com:99999/" + testKey,
		"path in authority":  "lg.example.com/x/" + testKey,
		"unbracketed ipv6":   "2001:db8::1/" + testKey,
		"bad host":           "bad_host/" + testKey,
		"encoded bad base64": "hlginit1.!!!not-base64!!!",
		"encoded bad json":   badJSON,
		"encoded bad ver":    badVersion,
	}
	for name, value := range cases {
		if _, err := Parse(value); err == nil {
			t.Errorf("%s: expected an error for %q", name, value)
		}
	}
}
