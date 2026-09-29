import { describe, expect, it } from "vitest";
import { certificateNotAfter } from "../src/acme";

// A real ECDSA P-256 self-signed certificate (generated with OpenSSL) whose
// notAfter is 2026-09-30T06:20:21Z. Used to verify the minimal DER walk reads
// the CA-granted validity instead of an assumed value.
const TEST_CERT_PEM = `-----BEGIN CERTIFICATE-----
MIIBizCCATGgAwIBAgIUbp6Qod+/JU4YKKJ0xRORNEx+tV8wCgYIKoZIzj0EAwIw
GzEZMBcGA1UEAwwQdGVzdC5leGFtcGxlLmNvbTAeFw0yNjA5MjMwNjIwMjFaFw0y
NjA5MzAwNjIwMjFaMBsxGTAXBgNVBAMMEHRlc3QuZXhhbXBsZS5jb20wWTATBgcq
hkjOPQIBBggqhkjOPQMBBwNCAATp/nfE3b5PkjjqlWM4YVmV3ABbtY9YohNdXnq4
lUvTG711S6HqpVOwdbG7zA5s4Tu3PHY0Fv8FIfSTTkz6huGio1MwUTAdBgNVHQ4E
FgQUb3ZHWjJua0Dy/o4zsCEVtv1B5JwwHwYDVR0jBBgwFoAUb3ZHWjJua0Dy/o4z
sCEVtv1B5JwwDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNIADBFAiBnNb4q
BeJa5+NcuCxvehQsVynQ/7Uz2BOMAh1x/146CwIhAP8qfSvRypswH910Hzq3mCqc
+QwVJwJM5ACv9NBJLEvA
-----END CERTIFICATE-----
`;

describe("certificate NotAfter parsing", () => {
  it("reads the real expiry from the PEM", () => {
    const expected = Math.floor(Date.UTC(2026, 8, 30, 6, 20, 21) / 1000);
    expect(certificateNotAfter(TEST_CERT_PEM)).toBe(expected);
  });

  it("returns null for input that is not a certificate", () => {
    expect(certificateNotAfter("not a pem")).toBeNull();
    expect(certificateNotAfter("-----BEGIN CERTIFICATE-----\nnonsense\n-----END CERTIFICATE-----")).toBeNull();
  });
});
