package connectauthority

import (
	"encoding/base64"
	"net/http"
	"strings"
)

func setRequestAuth(h http.Header, cfg ClientConfig) {
	if h == nil {
		return
	}
	if u := strings.TrimSpace(cfg.BasicUsername); u != "" {
		h.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(u+":"+cfg.BasicPassword)))
		return
	}
	if tok := strings.TrimSpace(cfg.BearerToken); tok != "" {
		h.Set("Authorization", "Bearer "+tok)
	}
}
