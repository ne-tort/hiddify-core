package hcore

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/ne-tort/pathology-core/v2/config"
	"golang.org/x/net/proxy"

	"github.com/sagernet/sing-box/option"
)

func getRandomAvailblePort() uint16 {
	port, release, err := acquireEphemeralPort(nil)
	if err != nil {
		panic(err)
	}
	release()
	return port
}

// reservedPorts must not be handed to TestEngine / RunInstance mixed inbound.
var reservedPorts = map[uint16]struct{}{
	12334: {}, // default mixed
	16756: {}, // clash api
	17078: {}, // common app ports
	17079: {},
	18020: {},
}

// acquireEphemeralPort binds :0 (or retries) and returns the port plus a release
// func that closes the hold listener. Call release immediately before Start binds.
func acquireEphemeralPort(extraExclude map[uint16]struct{}) (uint16, func(), error) {
	const maxAttempts = 32
	for i := 0; i < maxAttempts; i++ {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return 0, nil, err
		}
		port := uint16(listener.Addr().(*net.TCPAddr).Port)
		if _, bad := reservedPorts[port]; bad {
			_ = listener.Close()
			continue
		}
		if extraExclude != nil {
			if _, bad := extraExclude[port]; bad {
				_ = listener.Close()
				continue
			}
		}
		return port, func() { _ = listener.Close() }, nil
	}
	return 0, nil, fmt.Errorf("no ephemeral port available after %d attempts", maxAttempts)
}

func RunInstanceString(ctx context.Context, clientSettings *config.ClientOptions, proxiesInput string) (*PathologyInstance, error) {
	if clientSettings == nil {
		clientSettings = config.DefaultClientOptions()
	}

	singconfigs, err := config.ParseConfig(ctx, &config.ReadOptions{Content: proxiesInput}, true, clientSettings, false)
	if err != nil {
		return nil, err
	}
	return RunInstance(ctx, clientSettings, singconfigs)
}

func RunInstance(ctx context.Context, clientSettings *config.ClientOptions, singconfig *option.Options) (*PathologyInstance, error) {
	if clientSettings == nil {
		clientSettings = config.DefaultClientOptions()
	}
	clientSettings.EnableClashApi = false
	clientSettings.InboundOptions.MixedPort = getRandomAvailblePort()
	clientSettings.InboundOptions.EnableTun = false
	clientSettings.InboundOptions.EnableTunService = false
	clientSettings.InboundOptions.SetSystemProxy = false
	clientSettings.InboundOptions.TProxyPort = 0
	clientSettings.InboundOptions.DirectPort = 0
	clientSettings.InboundOptions.RedirectPort = 0
	clientSettings.Region = "other"
	clientSettings.BlockAds = false
	clientSettings.LogFile = "/dev/null"

	finalConfigs, err := config.BuildConfig(ctx, clientSettings, &config.ReadOptions{Options: singconfig})
	if err != nil {
		return nil, err
	}

	instance, err := NewService(ctx, *finalConfigs)
	if err != nil {
		return nil, err
	}

	<-time.After(250 * time.Millisecond)
	hservice := &PathologyInstance{
		StartedService: instance,
		ListenPort:     clientSettings.InboundOptions.MixedPort}
	hservice.PingCloudflare()
	return hservice, nil
}

// dialer, err := s.libbox.GetInstance().Router().Dialer(context.Background())

func (s *PathologyInstance) Close() error {
	return s.StartedService.CloseService()
}

func (s *PathologyInstance) GetContent(url string) (string, error) {
	return s.ContentFromURL("GET", url, 10*time.Second)
}

func (s *PathologyInstance) ContentFromURL(method string, url string, timeout time.Duration) (string, error) {
	if method == "" {
		return "", fmt.Errorf("empty method")
	}
	if url == "" {
		return "", fmt.Errorf("empty url")
	}

	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		return "", err
	}

	dialer, err := proxy.SOCKS5("tcp", fmt.Sprintf("127.0.0.1:%d", s.ListenPort), nil, proxy.Direct)
	if err != nil {
		return "", err
	}

	transport := &http.Transport{
		Dial: dialer.Dial,
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   timeout,
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return "", fmt.Errorf("request failed with status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	if body == nil {
		return "", fmt.Errorf("empty body")
	}

	return string(body), nil
}

func (s *PathologyInstance) PingCloudflare() (time.Duration, error) {
	return s.Ping("http://cp.cloudflare.com")
}

// func (s *HiddifyService) RawConnection(ctx context.Context, url string) (net.Conn, error) {
// 	return
// }

func (s *PathologyInstance) PingAverage(url string, count int) (time.Duration, error) {
	if count <= 0 {
		return -1, fmt.Errorf("count must be greater than 0")
	}

	var sum int
	real_count := 0
	for i := 0; i < count; i++ {
		delay, err := s.Ping(url)
		if err == nil {
			real_count++
			sum += int(delay.Milliseconds())
		} else if real_count == 0 && i > count/2 {
			return -1, fmt.Errorf("ping average failed")
		}

	}
	return time.Duration(sum / real_count * int(time.Millisecond)), nil
}

func (s *PathologyInstance) Ping(url string) (time.Duration, error) {
	startTime := time.Now()
	_, err := s.ContentFromURL("HEAD", url, 4*time.Second)
	if err != nil {
		return -1, err
	}
	duration := time.Since(startTime)
	return duration, nil
}
