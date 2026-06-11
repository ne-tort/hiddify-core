package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/sagernet/sing-box/internal/masquethin"
)

func main() {
	if len(os.Args) < 2 {
		os.Args = append(os.Args, "socks")
	}
	switch os.Args[1] {
	case "socks":
		runSOCKS(os.Args[2:])
	default:
		fmt.Fprintf(os.Stderr, "usage: %s socks [-listen 127.0.0.1:1081] [-server host:port] ...\n", os.Args[0])
		os.Exit(2)
	}
}

func runSOCKS(args []string) {
	fs := flag.NewFlagSet("socks", flag.ExitOnError)
	listen := fs.String("listen", "127.0.0.1:1081", "SOCKS5 listen address")
	server := fs.String("server", "127.0.0.1:4441", "MASQUE proxy host:port")
	tlsSNI := fs.String("tls-sni", "", "TLS ServerName (default: server host)")
	token := fs.String("token", "", "Bearer token")
	insecure := fs.Bool("insecure", false, "skip TLS verify")
	pipeUpload := fs.Bool("pipe-upload", false, "h3_pipe_up instead of h3_stream")
	_ = fs.Parse(args)

	host, portStr, err := net.SplitHostPort(*server)
	if err != nil {
		if !strings.Contains(*server, ":") {
			host = strings.TrimSpace(*server)
			portStr = "443"
		} else {
			log.Fatalf("server: %v", err)
		}
	}
	port, _ := strconv.Atoi(portStr)
	if port <= 0 {
		port = 443
	}
	if *pipeUpload {
		_ = os.Setenv("MASQUE_CONNECT_AUTHORITY_PIPE_UPLOAD", "1")
	} else {
		_ = os.Unsetenv("MASQUE_CONNECT_AUTHORITY_PIPE_UPLOAD")
	}

	cfg := masquethin.ClientConfig{
		Server:        host,
		ServerPort:    uint16(port),
		TLSServerName: strings.TrimSpace(*tlsSNI),
		BearerToken:   strings.TrimSpace(*token),
		InsecureTLS:   *insecure,
		UsePipeUpload: *pipeUpload,
	}
	if cfg.TLSServerName == "" {
		cfg.TLSServerName = host
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	log.Printf("masque-thin-client socks listen=%s server=%s h3_stream=%t", *listen, *server, !*pipeUpload)
	if err := masquethin.ServeSOCKS5(ctx, *listen, cfg); err != nil && ctx.Err() == nil {
		log.Fatalf("socks: %v", err)
	}
}
