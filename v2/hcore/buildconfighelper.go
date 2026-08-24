package hcore

import (
	"context"
	"encoding/json"
	"os"
	"strings"

	"github.com/ne-tort/pathology-core/v2/config"
	"github.com/ne-tort/pathology-core/v2/db"
	hcommon "github.com/ne-tort/pathology-core/v2/hcommon"
	hutils "github.com/ne-tort/pathology-core/v2/hutils"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/experimental/libbox"
	"github.com/sagernet/sing-box/option"
)

func BuildConfigJson(ctx context.Context, in *StartRequest) (string, error) {
	Log(LogLevel_DEBUG, LogType_CORE, "Stating Service ")

	parsedContent, err := BuildConfig(ctx, in)
	if err != nil {
		return "", err
	}
	res, err := parsedContent.MarshalJSONContext(ctx)
	return string(res), err
}

func BuildConfig(ctx context.Context, in *StartRequest) (*option.Options, error) {
	Log(LogLevel_DEBUG, LogType_CORE, "Building Config...")

	if in.EnableRawConfig {
		return config.ReadSingOptions(ctx, &config.ReadOptions{Content: in.ConfigContent, Path: in.ConfigPath})
	}

	// Prefer uncut import source (.src) so ignore-subscription-dns/route knobs re-apply,
	// but fall back to sliced .json when .src soft-parse yields no proxy leaves.
	// TestEngine already does this; Start used to stick to a Direct-only .src build
	// while the UI/ping still saw VLESS leaves in .json.
	if in.ConfigPath != "" {
		return buildConfigFromProfilePath(ctx, in.ConfigPath, in.ConfigContent)
	}

	return config.BuildConfig(ctx, static.ClientOptions, &config.ReadOptions{Content: in.ConfigContent, Path: in.ConfigPath})
}

func buildConfigFromProfilePath(ctx context.Context, configPath, configContent string) (*option.Options, error) {
	candidates := make([]string, 0, 2)
	if alt := config.ResolveConfigReadPath(configPath); alt != "" && alt != configPath {
		candidates = append(candidates, alt)
	}
	candidates = append(candidates, configPath)

	var (
		best       *option.Options
		bestLeaves int
		lastErr    error
	)
	for _, path := range candidates {
		built, err := config.ParseBuildConfig(ctx, static.ClientOptions, &config.ReadOptions{Path: path})
		if err != nil {
			lastErr = err
			Log(LogLevel_DEBUG, LogType_CORE, "profile build failed for ", path, ": ", err.Error())
			continue
		}
		n := countBuiltProxyLeaves(built)
		Log(LogLevel_DEBUG, LogType_CORE, "profile build ", path, " proxy leaves=", n)
		if n > bestLeaves {
			best = built
			bestLeaves = n
		}
		if n > 0 {
			if path != configPath {
				Log(LogLevel_DEBUG, LogType_CORE, "Building from profile source ", path)
			}
			return built, nil
		}
		if best == nil {
			best = built
		}
	}
	if best != nil {
		// Direct-only / empty leaf pool — still start (same as empty select→direct).
		return best, nil
	}
	if lastErr != nil {
		// Last resort: raw BuildConfig on the Flutter path (may skip soft-parse via Options).
		if fallback, err := config.BuildConfig(ctx, static.ClientOptions, &config.ReadOptions{Content: configContent, Path: configPath}); err == nil {
			return fallback, nil
		}
		return nil, lastErr
	}
	return config.BuildConfig(ctx, static.ClientOptions, &config.ReadOptions{Content: configContent, Path: configPath})
}

// countBuiltProxyLeaves counts selectable proxy outbounds/endpoints in a built config
// (excludes select/urltest/balancer/direct/block/dns and §hide§ tags).
func countBuiltProxyLeaves(opts *option.Options) int {
	if opts == nil {
		return 0
	}
	n := 0
	for _, ob := range opts.Outbounds {
		switch ob.Type {
		case C.TypeSelector, C.TypeURLTest, C.TypeBalancer, C.TypeBlock, C.TypeDNS, C.TypeDirect:
			continue
		default:
			if ob.Tag == "" || ob.Tag == config.OutboundDirectTag || strings.Contains(ob.Tag, "§hide§") {
				continue
			}
			n++
		}
	}
	for _, ep := range opts.Endpoints {
		if ep.Tag == "" || strings.Contains(ep.Tag, "§hide§") {
			continue
		}
		n++
	}
	return n
}

func (s *CoreService) Parse(ctx context.Context, in *ParseRequest) (*ParseResponse, error) {
	return Parse(libbox.FromContext(ctx, nil), in)
}

func Parse(ctx context.Context, in *ParseRequest) (*ParseResponse, error) {
	defer config.DeferPanicToError("parse", func(err error) {
		Log(LogLevel_FATAL, LogType_CONFIG, err.Error())
		StopAndAlert(MessageType_UNEXPECTED_ERROR, err.Error())
	})

  if static.ClientOptions == nil {
		static.ClientOptions = config.DefaultClientOptions()
	}

	// Client-side rule-set merge / DNS fragment actions.
	if in.Content != "" {
		var actionReq struct {
			HiddifyAction   string `json:"hiddify_action"`
			PathologyAction string `json:"pathology_action"`
		}
		if err := json.Unmarshal([]byte(in.Content), &actionReq); err == nil {
			action := actionReq.HiddifyAction
			if action == "" {
				action = actionReq.PathologyAction
			}
			if action != "" {
				switch action {
				case "merge_rulesets":
					var mergeReq struct {
						Inputs []string `json:"inputs"`
						Output string   `json:"output"`
					}
					if err := json.Unmarshal([]byte(in.Content), &mergeReq); err != nil {
						return &ParseResponse{ResponseCode: hcommon.ResponseCode_FAILED, Message: err.Error()}, nil
					}
					if err := config.MergeLocalRuleSets(mergeReq.Inputs, mergeReq.Output); err != nil {
						return &ParseResponse{ResponseCode: hcommon.ResponseCode_FAILED, Message: err.Error()}, nil
					}
					return &ParseResponse{ResponseCode: hcommon.ResponseCode_OK, Content: mergeReq.Output}, nil
				case "build_dns_fragment":
					var dnsReq struct {
						RemoteDetour string         `json:"remote_detour"`
						Options      map[string]any `json:"options"`
					}
					if err := json.Unmarshal([]byte(in.Content), &dnsReq); err != nil {
						return &ParseResponse{ResponseCode: hcommon.ResponseCode_FAILED, Message: err.Error()}, nil
					}
					rawOpts, _ := json.Marshal(dnsReq.Options)
					hopt := config.DefaultClientOptions()
					_ = json.Unmarshal(rawOpts, hopt)
					opts := option.Options{}
					if err := config.BuildDnsFragment(&opts, hopt, dnsReq.RemoteDetour); err != nil {
						return &ParseResponse{ResponseCode: hcommon.ResponseCode_FAILED, Message: err.Error()}, nil
					}
					out, err := json.Marshal(opts.DNS)
					if err != nil {
						return &ParseResponse{ResponseCode: hcommon.ResponseCode_FAILED, Message: err.Error()}, nil
					}
					return &ParseResponse{ResponseCode: hcommon.ResponseCode_OK, Content: string(out)}, nil
				default:
					return &ParseResponse{
						ResponseCode: hcommon.ResponseCode_FAILED,
						Message:      "unknown parse action: " + action,
					}, nil
				}
			}
		}
	}

	// Full config generation (debug/export): only config_path is set.
	// Apply current ClientOptions (incl. WARP inject) and do not rewrite the profile file.
	if in.TempPath == "" && in.Content == "" && in.ConfigPath != "" {
		readPath := in.ConfigPath
		if src := config.ProfileSourcePath(in.ConfigPath); src != "" {
			if st, err := os.Stat(src); err == nil && !st.IsDir() && st.Size() > 0 {
				readPath = src
			}
		}
		built, err := config.ParseBuildConfigBytes(ctx, static.ClientOptions, &config.ReadOptions{Path: readPath})
		if err != nil && readPath != in.ConfigPath {
			// .src may contain comment headers; fall back to sliced .json
			built, err = config.ParseBuildConfigBytes(ctx, static.ClientOptions, &config.ReadOptions{Path: in.ConfigPath})
		}
		if err != nil {
			return &ParseResponse{
				ResponseCode: hcommon.ResponseCode_FAILED,
				Message:      err.Error(),
			}, nil
		}
		return &ParseResponse{
			ResponseCode: hcommon.ResponseCode_OK,
			Content:      string(built),
		}, nil
	}

	path := in.TempPath
	if path == "" {
		path = in.ConfigPath
	}

	readOpt := &config.ReadOptions{Content: in.Content, Path: path}
	persistConfig := in.ConfigPath != "" && !config.IsScratchConfigPath(in.ConfigPath)
	// Preserve import source uncut: Build/Start re-parse this with current hopts
	// (DNS/route subscription toggles, etc.). Sliced .json remains for editor/legacy.
	if persistConfig {
		if raw, err := config.ReadContent(ctx, readOpt); err == nil && len(raw) > 0 {
			_ = hutils.WriteFileAtomic(config.ProfileSourcePath(in.ConfigPath), raw, 0o644)
		}
	}

	parsed, err := config.ParseConfigBytes(ctx, readOpt, true, static.ClientOptions, false)
	if err != nil {
		return &ParseResponse{
			ResponseCode: hcommon.ResponseCode_FAILED,
			Message:      err.Error(),
		}, nil
	}
	if persistConfig {
		err = hutils.WriteFileAtomic(in.ConfigPath, parsed, 0o644)
		if err != nil {
			return &ParseResponse{
				ResponseCode: hcommon.ResponseCode_FAILED,
				Message:      err.Error(),
			}, nil
		}
	}
	return &ParseResponse{
		ResponseCode: hcommon.ResponseCode_OK,
		Content:      string(parsed),
		Message:      "",
	}, nil
}

func (s *CoreService) ChangeClientSettings(ctx context.Context, in *ChangeClientSettingsRequest) (*CoreInfoResponse, error) {
	return ChangeClientSettings(in, true)
}

func ChangeClientSettings(in *ChangeClientSettingsRequest, insert bool) (*CoreInfoResponse, error) {
	static.ClientOptions = config.DefaultClientOptions()
	defer func() {
		switch static.ClientOptions.LogLevel {
		case "debug":
			static.logLevel = LogLevel_DEBUG
		case "info":
			static.logLevel = LogLevel_INFO
		case "warn":
			static.logLevel = LogLevel_WARNING
		case "error":
			static.logLevel = LogLevel_ERROR
		case "fatal":
			static.logLevel = LogLevel_FATAL
		case "trace":
			static.logLevel = LogLevel_TRACE
		default:
			static.logLevel = LogLevel_INFO
		}
		static.debug = static.debug || static.logLevel <= LogLevel_DEBUG
	}()

	if in.ClientSettingsJson == "" {
		return &CoreInfoResponse{}, nil
	}
	if insert {
		settings := db.GetTable[hcommon.AppSettings]()
		settings.UpdateInsert(&hcommon.AppSettings{
			Id:    "ClientSettingsJson",
			Value: in.ClientSettingsJson,
		})
	}

	err := json.Unmarshal([]byte(in.ClientSettingsJson), static.ClientOptions)
	if err != nil {
		return nil, err
	}

	return &CoreInfoResponse{}, nil
}

func (s *CoreService) GenerateConfig(ctx context.Context, in *GenerateConfigRequest) (*GenerateConfigResponse, error) {
	return GenerateConfig(libbox.FromContext(ctx, nil), in)
}

func GenerateConfig(ctx context.Context, in *GenerateConfigRequest) (*GenerateConfigResponse, error) {
	defer config.DeferPanicToError("generateConfig", func(err error) {
		Log(LogLevel_FATAL, LogType_CONFIG, err.Error())
		StopAndAlert(MessageType_UNEXPECTED_ERROR, err.Error())
	})
	if static.ClientOptions == nil {
		static.ClientOptions = config.DefaultClientOptions()
	}
	config, err := config.ParseBuildConfigBytes(ctx, static.ClientOptions, &config.ReadOptions{Path: in.Path})
	if err != nil {
		return nil, err
	}

	return &GenerateConfigResponse{
		ConfigContent: string(config),
	}, nil
}

func removeTunnelIfNeeded(options *option.Options) (tuninb *option.TunInboundOptions) {
	if hutils.TunAllowed() {
		return nil
	}

	// Create a new slice to hold the remaining inbounds
	newInbounds := make([]option.Inbound, 0, len(options.Inbounds))

	for _, inb := range options.Inbounds {
		if inb.Type == C.TypeTun {
			if d, ok := inb.Options.(option.TunInboundOptions); ok {
				tuninb = &d
			}

		} else {
			newInbounds = append(newInbounds, inb)
		}
	}

	options.Inbounds = newInbounds
	return tuninb
}
