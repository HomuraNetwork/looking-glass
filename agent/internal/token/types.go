package token

type BaseClaims struct {
	Type      string `json:"typ"`
	KID       string `json:"kid"`
	Node      string `json:"node"`
	IP        string `json:"ip"`
	IPBinding string `json:"ip_binding"`
	ExpiresAt int64  `json:"exp"`
	Nonce     string `json:"nonce"`
}

type DownloadClaims struct {
	BaseClaims
	Size   string `json:"size"`
	LinkID string `json:"link_id,omitempty"`
}

type JobClaims struct {
	BaseClaims
	Tool      string `json:"tool"`
	Target    string `json:"target"`
	IPVer     string `json:"ipver"`
	Count     int    `json:"count"`
	RemoteDNS bool   `json:"remote_dns,omitempty"`
}

type RequestContext struct {
	ClientIP string
	NodeID   string
}
