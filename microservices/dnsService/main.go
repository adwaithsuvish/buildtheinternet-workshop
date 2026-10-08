package main

import (
	"encoding/json"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
)

var (
	domainPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$`)
	registry      = make(map[string]string)
	registryMu    sync.RWMutex
)

type registerRequest struct {
	Domain string `json:"domain"`
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	data, err := json.Marshal(value)
	if err != nil {
		http.Error(w, `{"error":"failed to encode response"}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-Service-Endpoint")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.WriteHeader(status)
	_, _ = w.Write(data)
}

func cors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-Service-Endpoint")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func lookup(w http.ResponseWriter, r *http.Request) {
	domain := r.URL.Query().Get("domain")
	if !domainPattern.MatchString(domain) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Missing or invalid 'domain' query parameter"})
		return
	}
	registryMu.RLock()
	destination, ok := registry[domain]
	registryMu.RUnlock()
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "Domain not registered"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"domain": domain, "destination": destination})
}

func validServiceEndpoint(raw string) bool {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return false
	}
	parsed, err := url.Parse(trimmed)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" || parsed.User != nil {
		return false
	}
	if parsed.Path != "" && parsed.Path != "/" {
		return false
	}
	return true
}

func register(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	var request registerRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
	if err := decoder.Decode(&request); err != nil || !domainPattern.MatchString(request.Domain) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Missing required 'domain' field"})
		return
	}
	destination := strings.TrimSpace(r.Header.Get("X-Service-Endpoint"))
	if !validServiceEndpoint(destination) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "X-Service-Endpoint must be a complete http(s) URL"})
		return
	}
	registryMu.Lock()
	registry[request.Domain] = destination
	registryMu.Unlock()
	log.Printf("registered %s -> %s", request.Domain, destination)
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func main() {
	host := os.Getenv("DNS_HOST")
	if host == "" {
		host = "0.0.0.0"
	}
	port := os.Getenv("DNS_PORT")
	if port == "" {
		port = "8053"
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/lookup", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "Method not allowed"})
			return
		}
		lookup(w, r)
	})
	mux.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "Method not allowed"})
			return
		}
		register(w, r)
	})
	log.Printf("acm-dns listening on %s:%s", host, port)
	log.Fatal(http.ListenAndServe(net.JoinHostPort(host, port), cors(mux)))
}
