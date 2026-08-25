package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

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
	hostAppVersion string
	hostUiExe      string
	hostTray       bool
)

var hostTrayDone chan struct{}

type coreHostLock struct {
	PID       int    `json:"pid"`
	Listen    string `json:"listen"`
	Version   string `json:"version"`
	StartedAt string `json:"started_at"`
}

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
	commandHostServe.Flags().StringVar(&hostAppVersion, "app-version", "", "app version for lock-file handshake")
	commandHostServe.Flags().StringVar(&hostUiExe, "ui-exe", "", "Pathology UI executable for tray Open")
	commandHostServe.Flags().BoolVar(&hostTray, "tray", false, "show system tray (Phase 2)")
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

	if err := writeCoreHostLock(); err != nil {
		log.Warn("core host lock:", err)
	}
	defer removeCoreHostLock()

	fmt.Printf("Core Host listening on %s (Ctrl+C to stop)\n", hostListen)

	if hostTray {
		hostTrayDone = make(chan struct{})
		startHostTray(hostUiExe)
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	select {
	case <-sigChan:
		fmt.Println("Core Host shutting down (signal)")
	case <-hostTrayDone:
		fmt.Println("Core Host shutting down (tray quit)")
	}
	if _, err := hcore.Stop(); err != nil {
		log.Warn("host serve stop:", err)
	}
	hcore.CloseGrpcServer(hcore.SetupMode_GRPC_NORMAL_INSECURE)
}

func writeCoreHostLock() error {
	lock := coreHostLock{
		PID:       os.Getpid(),
		Listen:    hostListen,
		Version:   hostAppVersion,
		StartedAt: time.Now().UTC().Format(time.RFC3339),
	}
	raw, err := json.Marshal(lock)
	if err != nil {
		return err
	}
	path := filepath.Join(hostBasePath, "core_host.lock")
	return os.WriteFile(path, raw, 0o644)
}

func removeCoreHostLock() {
	path := filepath.Join(hostBasePath, "core_host.lock")
	_ = os.Remove(path)
}
