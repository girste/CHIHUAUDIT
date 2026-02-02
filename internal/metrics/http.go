package metrics

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// HTTPHandler provides HTTP endpoints for metrics and health
type HTTPHandler struct {
	registry  *Registry
	startTime time.Time
}

// NewHTTPHandler creates a new HTTP handler for metrics
func NewHTTPHandler(registry *Registry) *HTTPHandler {
	return &HTTPHandler{
		registry:  registry,
		startTime: time.Now(),
	}
}

// HandleHealth returns health status (200 OK if healthy)
func (h *HTTPHandler) HandleHealth(w http.ResponseWriter, r *http.Request) {
	health := map[string]interface{}{
		"status":  "healthy",
		"uptime":  time.Since(h.startTime).Seconds(),
		"version": "1.0.0",
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(health)
}

// HandleReady returns readiness status
func (h *HTTPHandler) HandleReady(w http.ResponseWriter, r *http.Request) {
	ready := map[string]interface{}{
		"status": "ready",
		"uptime": time.Since(h.startTime).Seconds(),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(ready)
}

// HandleMetrics returns Prometheus-format metrics
func (h *HTTPHandler) HandleMetrics(w http.ResponseWriter, r *http.Request) {
	metrics := h.registry.ExportPrometheus()

	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, metrics)
}

// StartServer starts the HTTP server for metrics (non-blocking)
func StartServer(addr string, registry *Registry) error {
	handler := NewHTTPHandler(registry)

	mux := http.NewServeMux()
	mux.HandleFunc("/health", handler.HandleHealth)
	mux.HandleFunc("/ready", handler.HandleReady)
	mux.HandleFunc("/metrics", handler.HandleMetrics)

	server := &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			fmt.Printf("Metrics server error: %v\n", err)
		}
	}()

	return nil
}
