//go:build with_masque

package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/pprof"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/sagernet/sing-box/internal/masquethin"
	"github.com/sagernet/sing-box/log"
	TM "github.com/sagernet/sing-box/transport/masque"

	"github.com/spf13/cobra"
)

var (
	masqueAuthorityListen     string
	masqueAuthorityCert       string
	masqueAuthorityKey        string
	masqueAuthorityToken      string
	masqueAuthorityAllowPriv  bool
	masqueAuthorityPprofListen string
)

var commandMasqueAuthorityServe = &cobra.Command{
	Use:   "masque-authority-serve",
	Short: "MASQUE CONNECT authority HTTP/3 only (no sing-box box)",
	Long:  "Thin-parity authority listener: same path as masque-thin-server, without box.New (isolates ServerEndpoint/box wrapper).",
	Run: func(cmd *cobra.Command, args []string) {
		if err := runMasqueAuthorityServe(); err != nil {
			log.Fatal(err)
		}
	},
}

func init() {
	commandMasqueAuthorityServe.Flags().StringVar(&masqueAuthorityListen, "listen", ":4439", "UDP listen address for HTTP/3")
	commandMasqueAuthorityServe.Flags().StringVar(&masqueAuthorityCert, "cert", "", "TLS certificate PEM path")
	commandMasqueAuthorityServe.Flags().StringVar(&masqueAuthorityKey, "key", "", "TLS key PEM path")
	commandMasqueAuthorityServe.Flags().StringVar(&masqueAuthorityToken, "token", "", "optional Bearer token")
	commandMasqueAuthorityServe.Flags().BoolVar(&masqueAuthorityAllowPriv, "allow-private", true, "allow private/loopback targets")
	commandMasqueAuthorityServe.Flags().StringVar(&masqueAuthorityPprofListen, "pprof", "", "optional pprof HTTP listen (e.g. 127.0.0.1:6060)")
	mainCommand.AddCommand(commandMasqueAuthorityServe)
}

func runMasqueAuthorityServe() error {
	if strings.TrimSpace(masqueAuthorityCert) == "" || strings.TrimSpace(masqueAuthorityKey) == "" {
		return fmt.Errorf("masque-authority-serve: -cert and -key required")
	}
	tlsCfg, err := TM.LoadAuthorityTLSFromPEM(masqueAuthorityCert, masqueAuthorityKey)
	if err != nil {
		return err
	}
	srvCfg := masquethin.ServerConfig{
		BearerToken:  strings.TrimSpace(masqueAuthorityToken),
		AllowPrivate: masqueAuthorityAllowPriv,
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect {
			masquethin.HandleCONNECTAuthority(w, r, srvCfg, (&net.Dialer{}).DialContext)
			return
		}
		http.NotFound(w, r)
	})
	as, err := TM.StartAuthorityHTTPServer(TM.AuthorityListenOptions{
		ListenAddr:      masqueAuthorityListen,
		TLSConfig:       tlsCfg,
		Handler:         handler,
		EnableDatagrams: false,
		QUICConfig:      masquethin.ServerQUICConfig(),
	})
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if p := strings.TrimSpace(masqueAuthorityPprofListen); p != "" {
		mux := http.NewServeMux()
		mux.HandleFunc("/debug/pprof/", pprof.Index)
		mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
		mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
		mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
		mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
		go func() {
			_ = http.ListenAndServe(p, mux)
		}()
		log.Info("masque-authority-serve pprof listen=", p)
	}
	go func() {
		<-ctx.Done()
		_ = as.Close()
	}()
	log.Info("masque-authority-serve listen=", masqueAuthorityListen, " relay_upload=", os.Getenv("MASQUE_THIN_RELAY_UPLOAD"))
	err = as.Serve()
	if err != nil && ctx.Err() == nil {
		return err
	}
	return nil
}
