package ray2sing

// LX-STUB: Hiddify XHTTPExtra / DownloadSettings used V2RayXHTTPBaseOptions +
// V2RayXHTTPDownloadOptions from hiddify-sing-box. sing-box-lx has a flatter
// V2RayXHTTPOptions without Download / BaseOptions. Extra XHTTP parse is ignored.

type XHTTPExtra struct {
	Host             string            `json:"host,omitempty"`
	Path             string            `json:"path,omitempty"`
	DownloadSettings *DownloadSettings `json:"downloadSettings,omitempty"`
}

type DownloadSettings struct {
	Address         string         `json:"address,omitempty"`
	Port            int            `json:"port,omitempty"`
	Security        string         `json:"security,omitempty"`
	TLSSettings     *TLSConfig     `json:"tlsSettings"`
	REALITYSettings *REALITYConfig `json:"realitySettings"`
}

type TLSConfig struct {
	Insecure    bool     `json:"allowInsecure"`
	ServerName  string   `json:"serverName"`
	ALPN        []string `json:"alpn"`
	Fingerprint string   `json:"fingerprint"`
}

type REALITYConfig struct {
	Fingerprint string `json:"fingerprint"`
	ServerName  string `json:"serverName"`
	PublicKey   string `json:"publicKey"`
	ShortId     string `json:"shortId"`
}
