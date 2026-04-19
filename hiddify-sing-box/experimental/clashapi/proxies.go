package clashapi

import (
	"context"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/sagernet/sing-box/adapter"
	rt "github.com/sagernet/sing-box/common/l3router"
	"github.com/sagernet/sing-box/common/urltest"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/group"
	l3routerendpoint "github.com/sagernet/sing-box/protocol/l3router"
	"github.com/sagernet/sing/common"
	F "github.com/sagernet/sing/common/format"
	"github.com/sagernet/sing/common/json/badjson"
	N "github.com/sagernet/sing/common/network"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
)

func proxyRouter(server *Server, router adapter.Router) http.Handler {
	r := chi.NewRouter()
	r.Get("/", getProxies(server))

	r.Route("/{name}", func(r chi.Router) {
		r.Use(parseProxyName, findProxyByName(server))
		r.Get("/", getProxy(server))
		r.Get("/delay", getProxyDelay(server))
		r.Get("/metrics", getProxyMetrics(server))
		// Runtime route mutation is an optional ops API; static JSON routes are the primary path.
		r.Post("/routes", upsertProxyRoute(server))
		r.Delete("/routes/{id}", removeProxyRoute(server))
		r.Put("/", updateProxy)
	})
	return r
}

func parseProxyName(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := getEscapeParam(r, "name")
		ctx := context.WithValue(r.Context(), CtxKeyProxyName, name)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func findProxyByName(server *Server) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			name := r.Context().Value(CtxKeyProxyName).(string)
			proxy, exist := findProxyOrEndpointByName(server, name)
			if !exist {
				render.Status(r, http.StatusNotFound)
				render.JSON(w, r, ErrNotFound)
				return
			}
			ctx := context.WithValue(r.Context(), CtxKeyProxy, proxy)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func proxyInfo(server *Server, detour adapter.Outbound) *badjson.JSONObject {
	var info badjson.JSONObject
	var clashType string
	switch detour.Type() {
	case C.TypeBlock:
		clashType = "Reject"
	default:
		clashType = C.ProxyDisplayName(detour.Type())
	}
	info.Put("type", clashType)
	info.Put("name", detour.Tag())
	info.Put("udp", common.Contains(detour.Network(), N.NetworkUDP))
	delayHistory := server.urlTestHistory.LoadURLTestHistory(adapter.OutboundTag(detour))
	if delayHistory != nil {
		info.Put("history", []*adapter.URLTestHistory{delayHistory})
	} else {
		info.Put("history", []*adapter.URLTestHistory{})
	}
	if group, isGroup := detour.(adapter.OutboundGroup); isGroup {
		info.Put("now", group.Now())
		info.Put("all", group.All())
	}
	if l3, ok := detour.(l3RouterMetricsProvider); ok {
		info.Put("l3router", map[string]any{
			"metrics": l3.SnapshotMetrics(),
		})
	}
	return &info
}

func getProxies(server *Server) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		var proxyMap badjson.JSONObject
		outbounds := common.Filter(server.outbound.Outbounds(), func(detour adapter.Outbound) bool {
			return detour.Tag() != ""
		})
		outbounds = append(outbounds, common.Map(common.Filter(server.endpoint.Endpoints(), func(detour adapter.Endpoint) bool {
			return detour.Tag() != ""
		}), func(it adapter.Endpoint) adapter.Outbound {
			return it
		})...)

		allProxies := make([]string, 0, len(outbounds))

		for _, detour := range outbounds {
			switch detour.Type() {
			case C.TypeDirect, C.TypeBlock, C.TypeDNS:
				continue
			}
			allProxies = append(allProxies, detour.Tag())
		}

		defaultTag := server.outbound.Default().Tag()

		sort.SliceStable(allProxies, func(i, j int) bool {
			return allProxies[i] == defaultTag
		})

		// fix clash dashboard
		proxyMap.Put("GLOBAL", map[string]any{
			"type":    "Fallback",
			"name":    "GLOBAL",
			"udp":     true,
			"history": []*adapter.URLTestHistory{},
			"all":     allProxies,
			"now":     defaultTag,
		})

		for i, detour := range outbounds {
			var tag string
			if detour.Tag() == "" {
				tag = F.ToString(i)
			} else {
				tag = detour.Tag()
			}
			proxyMap.Put(tag, proxyInfo(server, detour))
		}
		var responseMap badjson.JSONObject
		responseMap.Put("proxies", &proxyMap)
		response, err := responseMap.MarshalJSON()
		if err != nil {
			render.Status(r, http.StatusInternalServerError)
			render.JSON(w, r, newError(err.Error()))
			return
		}
		w.Write(response)
	}
}

func getProxy(server *Server) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		proxy := r.Context().Value(CtxKeyProxy).(adapter.Outbound)
		response, err := proxyInfo(server, proxy).MarshalJSON()
		if err != nil {
			render.Status(r, http.StatusInternalServerError)
			render.JSON(w, r, newError(err.Error()))
			return
		}
		w.Write(response)
	}
}

type UpdateProxyRequest struct {
	Name string `json:"name"`
}

func updateProxy(w http.ResponseWriter, r *http.Request) {
	req := UpdateProxyRequest{}
	if err := render.DecodeJSON(r.Body, &req); err != nil {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, ErrBadRequest)
		return
	}

	proxy := r.Context().Value(CtxKeyProxy).(adapter.Outbound)
	selector, ok := proxy.(*group.Selector)
	if !ok {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, newError("Must be a Selector"))
		return
	}

	if !selector.SelectOutbound(req.Name) {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, newError("Selector update error: not found"))
		return
	}

	render.NoContent(w, r)
}

func getProxyDelay(server *Server) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query()
		url := query.Get("url")
		if strings.HasPrefix(url, "http://") {
			url = ""
		}
		timeout, err := strconv.ParseInt(query.Get("timeout"), 10, 16)
		if err != nil {
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, ErrBadRequest)
			return
		}

		proxy := r.Context().Value(CtxKeyProxy).(adapter.Outbound)
		ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond*time.Duration(timeout))
		defer cancel()

		delay, err := urltest.URLTest(ctx, url, proxy)
		defer func() {
			realTag := group.RealTag(proxy)
			if err != nil {
				server.urlTestHistory.DeleteURLTestHistory(realTag)
			} else {
				server.urlTestHistory.StoreURLTestHistory(realTag, &adapter.URLTestHistory{
					Time:  time.Now(),
					Delay: delay,
				})
			}
		}()

		if ctx.Err() != nil {
			render.Status(r, http.StatusGatewayTimeout)
			render.JSON(w, r, ErrRequestTimeout)
			return
		}

		if err != nil || delay == 0 {
			render.Status(r, http.StatusServiceUnavailable)
			render.JSON(w, r, newError("An error occurred in the delay test"))
			return
		}

		render.JSON(w, r, render.M{
			"delay": delay,
		})
	}
}

type l3RouterRouteRequest struct {
	option.L3RouterPeerOptions
}

type l3RouterControlResponse struct {
	Status string `json:"status"`
	Tag    string `json:"tag"`
	PeerID uint64 `json:"peer_id,omitempty"`
}

type l3RouterMetricsProvider interface {
	SnapshotMetrics() l3routerendpoint.Metrics
}

type l3RouterRouteController interface {
	UpsertRoute(rt.Route) error
	RemoveRoute(rt.RouteID)
}

func l3routerCapabilities(proxy adapter.Outbound) (l3RouterMetricsProvider, l3RouterRouteController, bool) {
	metricsProvider, hasMetrics := proxy.(l3RouterMetricsProvider)
	routeController, hasRoutes := proxy.(l3RouterRouteController)
	return metricsProvider, routeController, hasMetrics && hasRoutes
}

func getProxyMetrics(_ *Server) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		proxy := r.Context().Value(CtxKeyProxy).(adapter.Outbound)
		l3Metrics, _, ok := l3routerCapabilities(proxy)
		if !ok {
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, newError("proxy does not support metrics"))
			return
		}
		metrics := l3Metrics.SnapshotMetrics()
		render.JSON(w, r, map[string]any{
			"type":    proxy.Type(),
			"name":    proxy.Tag(),
			"metrics": metrics,
			"totals":  metrics,
			"endpoints": []l3RouterEndpointMetrics{
				{
					Type:    proxy.Type(),
					Tag:     proxy.Tag(),
					Metrics: metrics,
				},
			},
		})
	}
}

func upsertProxyRoute(server *Server) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		proxy := r.Context().Value(CtxKeyProxy).(adapter.Outbound)
		_, routeController, ok := l3routerCapabilities(proxy)
		if !ok {
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, newError("proxy does not support routes"))
			return
		}
		var req l3RouterRouteRequest
		if err := decodeJSONBody(w, r, &req, server.l3RouterStrictValidation); err != nil {
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, newError(err.Error()))
			return
		}
		route, err := l3routerendpoint.ParseRouteOptions(req.L3RouterPeerOptions)
		if err != nil {
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, newError(err.Error()))
			return
		}
		if err := routeController.UpsertRoute(route); err != nil {
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, newError(err.Error()))
			return
		}
		render.JSON(w, r, l3RouterControlResponse{
			Status: "ok",
			Tag:    proxy.Tag(),
			PeerID: req.PeerID,
		})
	}
}

func removeProxyRoute(_ *Server) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		proxy := r.Context().Value(CtxKeyProxy).(adapter.Outbound)
		_, routeController, ok := l3routerCapabilities(proxy)
		if !ok {
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, newError("proxy does not support routes"))
			return
		}
		idText := chi.URLParam(r, "id")
		id, err := strconv.ParseUint(idText, 10, 64)
		if err != nil || id == 0 {
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, newError("peer id must be a non-zero unsigned integer"))
			return
		}
		routeController.RemoveRoute(rt.RouteID(id))
		render.JSON(w, r, l3RouterControlResponse{
			Status: "ok",
			Tag:    proxy.Tag(),
			PeerID: id,
		})
	}
}

func findProxyOrEndpointByName(server *Server, name string) (adapter.Outbound, bool) {
	if proxy, exist := server.outbound.Outbound(name); exist {
		return proxy, true
	}
	if ep, exist := server.endpoint.Get(name); exist {
		outboundEp, ok := ep.(adapter.Outbound)
		if ok {
			return outboundEp, true
		}
	}
	return nil, false
}
