package main



import (

	"context"

	"flag"

	"fmt"

	"log"

	"net"

	"net/http"

	"os"

	"os/signal"

	"strings"

	"syscall"



	"github.com/sagernet/sing-box/internal/masquethin"

	TM "github.com/sagernet/sing-box/transport/masque"

)



func main() {

	listen := flag.String("listen", ":4441", "UDP listen address for HTTP/3 MASQUE")

	certFile := flag.String("cert", "", "TLS certificate PEM")

	keyFile := flag.String("key", "", "TLS key PEM")

	token := flag.String("token", "", "optional Bearer token (empty = open)")

	allowPrivate := flag.Bool("allow-private", true, "allow private/loopback targets")

	flag.Parse()



	if *certFile == "" || *keyFile == "" {

		log.Fatal("masque-thin-server: -cert and -key required")

	}

	tlsCfg, err := TM.LoadAuthorityTLSFromPEM(*certFile, *keyFile)

	if err != nil {

		log.Fatalf("load cert: %v", err)

	}



	srvCfg := masquethin.ServerConfig{

		BearerToken:  strings.TrimSpace(*token),

		AllowPrivate: *allowPrivate,

	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		if r.Method == http.MethodConnect {

			masquethin.HandleCONNECTAuthority(w, r, srvCfg, (&net.Dialer{}).DialContext)

			return

		}

		http.NotFound(w, r)

	})



	as, err := TM.StartAuthorityHTTPServer(TM.AuthorityListenOptions{

		ListenAddr:      *listen,

		TLSConfig:       tlsCfg,

		Handler:         handler,

		EnableDatagrams: false,

		QUICConfig:      masquethin.ServerQUICConfig(),

	})

	if err != nil {

		log.Fatalf("listen: %v", err)

	}



	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)

	defer stop()



	go func() {

		<-ctx.Done()

		_ = as.Close()

	}()



	log.Printf("masque-thin-server listen=%s relay_upload=%s", *listen, os.Getenv("MASQUE_THIN_RELAY_UPLOAD"))

	if err := as.Serve(); err != nil && ctx.Err() == nil {

		fmt.Fprintf(os.Stderr, "serve: %v\n", err)

		os.Exit(1)

	}

}


