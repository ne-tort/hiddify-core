package sdk

import (
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"runtime"
	"strings"

	"github.com/ne-tort/pathology-core/v2/config"
	hcore "github.com/ne-tort/pathology-core/v2/hcore"
	"github.com/sagernet/sing-box/option"
)

func RunInstance(ctx context.Context, clientSettings *config.ClientOptions, singconfig *option.Options) (*hcore.PathologyInstance, error) {
	return hcore.RunInstance(ctx, clientSettings, singconfig)
}

func ParseConfig(ctx context.Context, clientSettings *config.ClientOptions, configStr string) (*option.Options, error) {
	if clientSettings == nil {
		clientSettings = config.DefaultClientOptions()
	}
	if strings.HasPrefix(configStr, "http://") || strings.HasPrefix(configStr, "https://") {
		client := &http.Client{}
		configPath := strings.Split(configStr, "\n")[0]
		// Create a new request
		req, err := http.NewRequest("GET", configPath, nil)
		if err != nil {
			fmt.Println("Error creating request:", err)
			return nil, err
		}
		req.Header.Set("User-Agent", "Pathology/2.3.1 ("+runtime.GOOS+") like ClashMeta v2ray sing-box")
		resp, err := client.Do(req)
		if err != nil {
			fmt.Println("Error making GET request:", err)
			return nil, err
		}
		defer resp.Body.Close()

		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read config body: %w", err)
		}
		configStr = string(body)
	}
	return config.ParseBuildConfig(ctx, clientSettings, &config.ReadOptions{Content: configStr})
}
