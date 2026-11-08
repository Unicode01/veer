package app

import (
	"net/http"
	"net/http/pprof"
)

// registerPprofHandlers serves the daemon's Go runtime profiles behind the
// management token. A token holder already administers the host network, so
// profiles grant no new authority. They cover only this process: rule and
// range workers, the shared proxy and plugin hosts run as separate processes.
//
// net/http/pprof rejects a CPU profile or trace whose duration reaches the
// API write timeout, so callers pass seconds below apiServerWriteTimeout.
func registerPprofHandlers(mux *http.ServeMux, cfg *Config) {
	mux.HandleFunc("/debug/pprof/", authMiddleware(cfg, pprof.Index))
	mux.HandleFunc("/debug/pprof/cmdline", authMiddleware(cfg, pprof.Cmdline))
	mux.HandleFunc("/debug/pprof/profile", authMiddleware(cfg, pprof.Profile))
	mux.HandleFunc("/debug/pprof/symbol", authMiddleware(cfg, pprof.Symbol))
	mux.HandleFunc("/debug/pprof/trace", authMiddleware(cfg, pprof.Trace))
}
