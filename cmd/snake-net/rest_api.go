package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"
	"strconv"
	"time"

	"github.com/sem-hub/snake-net/internal/clients"
	"github.com/sem-hub/snake-net/internal/configs"
)

func startRESTAPIServer(ctx context.Context, port int) {
	logger := configs.GetLogger("main")
	if port <= 0 {
		return
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/metrics", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		ipParam := r.URL.Query().Get("ip")
		if ipParam == "" {
			http.Error(w, "missing ip query parameter", http.StatusBadRequest)
			return
		}

		ip, err := netip.ParseAddr(ipParam)
		if err != nil {
			http.Error(w, "invalid ip format", http.StatusBadRequest)
			return
		}

		metrics, ok := clients.GetClientMetricsByIP(ip)
		if !ok {
			http.Error(w, "client not found", http.StatusNotFound)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(metrics); err != nil {
			logger.Error("REST API encode error", "error", err)
		}
	})
	mux.HandleFunc("/api/v1/clients", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		connectedClients := clients.GetConnectedClientsInfo()

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(connectedClients); err != nil {
			logger.Error("REST API encode error", "error", err)
		}
	})

	server := &http.Server{
		Addr:              ":" + strconv.Itoa(port),
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("REST API shutdown error", "error", err)
		}
	}()

	go func() {
		logger.Info("REST API started", "port", port)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("REST API server error", "error", err)
		}
	}()
}
