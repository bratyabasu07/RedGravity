package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/gorilla/mux"
)

// Server represents the API server
type Server struct {
	Router *mux.Router
	Port   int
	APIKey string
}

// NewServer creates a new API server
func NewServer(port int, apiKey string) *Server {
	return &Server{
		Router: mux.NewRouter(),
		Port:   port,
		APIKey: apiKey,
	}
}

// ScanRequest represents a scan request
type ScanRequest struct {
	Target string `json:"target"`
	Mode   string `json:"mode"`
	Format string `json:"format"`
}

// ScanResponse represents a scan response
type ScanResponse struct {
	ScanID  string `json:"scan_id"`
	Status  string `json:"status"`
	Message string `json:"message"`
}

// Start starts the API server
func (s *Server) Start() error {
	s.setupRoutes()

	addr := fmt.Sprintf(":%d", s.Port)
	fmt.Printf("[API] Starting server on %s\n", addr)

	server := &http.Server{
		Addr:         addr,
		Handler:      s.Router,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	return server.ListenAndServe()
}

// setupRoutes configures API routes
func (s *Server) setupRoutes() {
	s.Router.Use(s.authMiddleware)

	s.Router.HandleFunc("/api/scan", s.handleCreateScan).Methods("POST")
	s.Router.HandleFunc("/api/scan/{id}", s.handleGetScan).Methods("GET")
	s.Router.HandleFunc("/api/history", s.handleGetHistory).Methods("GET")
	s.Router.HandleFunc("/api/health", s.handleHealth).Methods("GET")
}

// authMiddleware authenticates requests
func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/health" {
			next.ServeHTTP(w, r)
			return
		}

		apiKey := r.Header.Get("X-API-Key")
		if apiKey != s.APIKey {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// handleCreateScan creates a new scan
func (s *Server) handleCreateScan(w http.ResponseWriter, r *http.Request) {
	var req ScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// TODO: Start scan asynchronously
	scanID := fmt.Sprintf("scan_%d", time.Now().Unix())

	resp := ScanResponse{
		ScanID:  scanID,
		Status:  "queued",
		Message: "Scan initiated successfully",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// handleGetScan retrieves scan status
func (s *Server) handleGetScan(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scanID := vars["id"]

	// TODO: Get scan status from database
	resp := map[string]interface{}{
		"scan_id": scanID,
		"status":  "completed",
		"results": map[string]interface{}{},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// handleGetHistory retrieves scan history
func (s *Server) handleGetHistory(w http.ResponseWriter, r *http.Request) {
	// TODO: Get scan history from database
	history := []map[string]interface{}{
		{
			"scan_id":   "scan_123",
			"target":    "example.com",
			"timestamp": time.Now().Format(time.RFC3339),
			"status":    "completed",
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(history)
}

// handleHealth returns health status
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	health := map[string]string{
		"status": "healthy",
		"time":   time.Now().Format(time.RFC3339),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(health)
}

// Shutdown gracefully shuts down the server
func (s *Server) Shutdown(ctx context.Context) error {
	// Implement graceful shutdown
	return nil
}
