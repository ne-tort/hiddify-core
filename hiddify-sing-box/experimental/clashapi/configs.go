package clashapi

import (
	"net/http"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	l3routerendpoint "github.com/sagernet/sing-box/protocol/l3router"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
)

func configRouter(server *Server, logFactory log.Factory) http.Handler {
	r := chi.NewRouter()
	r.Get("/", getConfigs(server, logFactory))
	r.Put("/", updateConfigs)
	r.Patch("/", patchConfigs(server))
	return r
}

type configSchema struct {
	Port        int    `json:"port"`
	SocksPort   int    `json:"socks-port"`
	RedirPort   int    `json:"redir-port"`
	TProxyPort  int    `json:"tproxy-port"`
	MixedPort   int    `json:"mixed-port"`
	AllowLan    bool   `json:"allow-lan"`
	BindAddress string `json:"bind-address"`
	Mode        string `json:"mode"`
	// sing-box added
	ModeList []string       `json:"mode-list"`
	LogLevel string         `json:"log-level"`
	IPv6     bool           `json:"ipv6"`
	Tun      map[string]any `json:"tun"`
	L3Router map[string]any `json:"l3router,omitempty"`
}

func getConfigs(server *Server, logFactory log.Factory) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		logLevel := logFactory.Level()
		if logLevel == log.LevelTrace {
			logLevel = log.LevelDebug
		} else if logLevel < log.LevelError {
			logLevel = log.LevelError
		}
		l3Endpoints, l3Totals := collectL3RouterMetrics(server.endpoint.Endpoints())
		render.JSON(w, r, &configSchema{
			Mode:        server.mode,
			ModeList:    server.modeList,
			BindAddress: "*",
			LogLevel:    log.FormatLevel(logLevel),
			L3Router: map[string]any{
				"endpoints": l3Endpoints,
				"totals":    l3Totals,
			},
		})
	}
}

func patchConfigs(server *Server) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		var newConfig configSchema
		err := decodeJSONBody(w, r, &newConfig, server.l3RouterStrictValidation)
		if err != nil {
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, newError(err.Error()))
			return
		}
		if newConfig.Mode != "" {
			server.SetMode(newConfig.Mode)
		}
		render.NoContent(w, r)
	}
}

func updateConfigs(w http.ResponseWriter, r *http.Request) {
	render.NoContent(w, r)
}

type l3RouterEndpointMetrics struct {
	Type    string                   `json:"type"`
	Tag     string                   `json:"tag"`
	Metrics l3routerendpoint.Metrics `json:"metrics"`
}

func collectL3RouterMetrics(endpoints []adapter.Endpoint) ([]l3RouterEndpointMetrics, l3routerendpoint.Metrics) {
	result := make([]l3RouterEndpointMetrics, 0, len(endpoints))
	var totals l3routerendpoint.Metrics
	for _, ep := range endpoints {
		if ep.Type() != C.TypeL3Router {
			continue
		}
		snapshotter, ok := ep.(interface {
			SnapshotMetrics() l3routerendpoint.Metrics
		})
		if !ok {
			continue
		}
		metrics := snapshotter.SnapshotMetrics()
		result = append(result, l3RouterEndpointMetrics{
			Type:    ep.Type(),
			Tag:     ep.Tag(),
			Metrics: metrics,
		})
		totals.IngressPackets += metrics.IngressPackets
		totals.ForwardPackets += metrics.ForwardPackets
		totals.DropPackets += metrics.DropPackets
		totals.DropNoIngressRoute += metrics.DropNoIngressRoute
		totals.DropNoEgressRoute += metrics.DropNoEgressRoute
		totals.DropDecisionOther += metrics.DropDecisionOther
		totals.DropQueueOverflow += metrics.DropQueueOverflow
		totals.DropQueueNoSession += metrics.DropQueueNoSession
		totals.EgressWriteFail += metrics.EgressWriteFail
		totals.WriteTimeout += metrics.WriteTimeout
		totals.QueueOverflow += metrics.QueueOverflow
		totals.DropNoSession += metrics.DropNoSession
		totals.DropFilterSource += metrics.DropFilterSource
		totals.DropFilterDestination += metrics.DropFilterDestination
		totals.FragmentDrops += metrics.FragmentDrops
		totals.StaticLoadOK += metrics.StaticLoadOK
		totals.StaticLoadError += metrics.StaticLoadError
		totals.ControlUpsertOK += metrics.ControlUpsertOK
		totals.ControlRemoveOK += metrics.ControlRemoveOK
		totals.ControlErrors += metrics.ControlErrors
		totals.NetworkResets += metrics.NetworkResets
		totals.SchedulerDrops += metrics.SchedulerDrops
		totals.AQMDrops += metrics.AQMDrops
		totals.QueueDepth += metrics.QueueDepth
		if metrics.QueueDepthHigh > totals.QueueDepthHigh {
			totals.QueueDepthHigh = metrics.QueueDepthHigh
		}
		if metrics.QueueDelayMicrosP50 > totals.QueueDelayMicrosP50 {
			totals.QueueDelayMicrosP50 = metrics.QueueDelayMicrosP50
		}
		if metrics.QueueDelayMicrosP95 > totals.QueueDelayMicrosP95 {
			totals.QueueDelayMicrosP95 = metrics.QueueDelayMicrosP95
		}
		if metrics.QueueDelayMicrosP99 > totals.QueueDelayMicrosP99 {
			totals.QueueDelayMicrosP99 = metrics.QueueDelayMicrosP99
		}
	}
	return result, totals
}
