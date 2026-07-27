package ray2sing

import (
	"strconv"

	T "github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

// SudokuSingbox maps sudoku:// share links to SudokuOutboundOptions.
//
//	sudoku://KEY@host:443/?aead_method=chacha20-poly1305&table_type=prefer_ascii&padding_min=5&padding_max=15
//	sudoku://host:443/?key=UUID&aead_method=aes-128-gcm
func SudokuSingbox(rawURL string) (*T.Outbound, error) {
	u, err := ParseUrl(rawURL, 443)
	if err != nil {
		return nil, err
	}
	if u.Hostname == "" {
		return nil, E.New("sudoku: server is required")
	}
	decoded := u.Params
	key := firstNonEmpty(u.Username, decoded["key"])
	if key == "" {
		return nil, E.New("sudoku: key is required")
	}
	opts := &T.SudokuOutboundOptions{
		DialerOptions: getDialerOptions(decoded),
		ServerOptions: u.GetServerOption(),
		Key:           key,
		AEADMethod:    getOneOfN(decoded, "", "aead method", "aead"),
		TableType:     getOneOfN(decoded, "", "table type", "table"),
		CustomTable:   getOneOfN(decoded, "", "custom table"),
		Multiplex:     getOneOfN(decoded, "", "multiplex", "mux"),
	}
	if v := getOneOfN(decoded, "", "padding min"); v != "" {
		if n, e := strconv.Atoi(v); e == nil {
			opts.PaddingMin = &n
		}
	}
	if v := getOneOfN(decoded, "", "padding max"); v != "" {
		if n, e := strconv.Atoi(v); e == nil {
			opts.PaddingMax = &n
		}
	}
	if v := getOneOfN(decoded, "", "enable pure downlink", "pure downlink"); v != "" {
		b := v == "1" || v == "true"
		opts.EnablePureDownlink = &b
	}
	httpmaskDisable := decoded["httpmask"] == "0" || decoded["httpmask"] == "false" || decoded["httpmask disable"] == "1"
	httpmaskMode := getOneOfN(decoded, "", "httpmask mode")
	if httpmaskDisable || httpmaskMode != "" {
		opts.HTTPMask = &T.SudokuHTTPMaskOptions{
			Disable:  httpmaskDisable,
			Mode:     firstNonEmpty(httpmaskMode, "legacy"),
			TLS:      decoded["httpmask tls"] == "1" || decoded["httpmask tls"] == "true",
			Host:     getOneOfN(decoded, "", "httpmask host"),
			PathRoot: getOneOfN(decoded, "", "httpmask path", "path root"),
		}
	}
	return &T.Outbound{
		Tag:     u.Name,
		Type:    "sudoku",
		Options: opts,
	}, nil
}
