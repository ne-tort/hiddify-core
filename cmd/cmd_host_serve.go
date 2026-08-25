package cmd

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	hcore "github.com/ne-tort/pathology-core/v2/hcore"
	"github.com/sagernet/sing-box/log"

	"github.com/spf13/cobra"
)

var (
	hostBasePath   string
	hostWorkingDir string
	hostTempDir    string
	hostListen     string
	hostDebug      bool
)

var commandHostServe = &cobra.Command{
	Use:   "serve",
	Short: "Run pathology-core gRPC host (Setup only, no VPN Start)",
	Long:  "Headless Core Host for Phase 1: binds loopback gRPC and waits for UI or tray clients.",
	Run:   runHostServe,
}

var commandHost = &cobra.Command{
	Use:   "host",
	Short: "Core Host control plane",
}

func init() {
	commandHostServe.Flags().StringVar(&hostBasePath, "base", "", "portable base / app support directory")
	commandHostServe.Flags().StringVar(&hostWorkingDir, "working", "", "working directory (profiles, configs)")
	commandHostServe.Flags().StringVar(&hostTempDir, "temp", "", "temp directory")
	commandHostServe.Flags().StringVar(&hostListen, "listen", "127.0.0.1:17078", "gRPC listen address (loopback only)")
	commandHostServe.Flags().BoolVar(&hostDebug, "debug", false, "enable debug logging and pprof")
	commandHostServe.MarkFlagRequired("base")
	commandHostServe.MarkFlagRequired("working")
	commandHostServe.MarkFlagRequired("temp")

	commandHost.AddCommand(commandHostServe)
	mainCommand.AddCommand(commandHost)
}

func runHostServe(cmd *cobra.Command, args []string) {
	if err := hcore.Setup(
		&hcore.SetupRequest{
			BasePath:          hostBasePath,
			WorkingDir:        hostWorkingDir,
			TempDir:           hostTempDir,
			FlutterStatusPort: 0,
			Debug:             hostDebug,
			Mode:              hcore.SetupMode_GRPC_NORMAL_INSECURE,
			Listen:            hostListen,
		},
		nil,
	); err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Core Host listening on %s (Ctrl+C to stop)\n", hostListen)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan

	fmt.Println("Core Host shutting down")
	if _, err := hcore.Stop(); err != nil {
		log.Warn("host serve stop:", err)
	}
	hcore.CloseGrpcServer(hcore.SetupMode_GRPC_NORMAL_INSECURE)
}
