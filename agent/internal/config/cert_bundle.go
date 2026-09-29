package config

type CertificateBundle struct {
	Version       int64  `json:"version"`
	NodeID        string `json:"node_id"`
	Domain        string `json:"domain"`
	IssuedAt      int64  `json:"issued_at"`
	CertExpiresAt int64  `json:"cert_expires_at"`
	CertPEM       string `json:"cert_pem"`
	KeyPEM        string `json:"key_pem"`
	CAPEM         string `json:"ca_pem"`
	ConfigKID     string `json:"config_kid"`
	Signature     string `json:"signature"`
	// NodeBundleID is the controller's row id for this delivery, taken from
	// the response header. It is not part of the signed payload.
	NodeBundleID string `json:"-"`
}
