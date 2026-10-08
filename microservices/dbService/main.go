package main

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"errors"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

const maxBodyBytes = 16 * 1024

type config struct {
	bindAddress     string
	port            string
	database        string
	serviceToken    string
	dnsURL          string
	dnsToken        string
	serviceDomain   string
	serviceEndpoint string
}

func env(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}

func loadConfig() config {
	cfg := config{
		bindAddress:     env("BIND_ADDRESS", "127.0.0.1"),
		port:            env("PORT", "5001"),
		database:        env("DB_PATH", "users.db"),
		serviceToken:    env("INTERNAL_SERVICE_TOKEN", ""),
		dnsURL:          strings.TrimRight(os.Getenv("DNS_URL"), "/"),
		dnsToken:        env("DNS_SERVICE_TOKEN", ""),
		serviceDomain:   env("SERVICE_DOMAIN", "acm-db"),
		serviceEndpoint: strings.TrimRight(os.Getenv("SERVICE_ENDPOINT"), "/"),
	}
	if cfg.serviceEndpoint == "" && cfg.bindAddress == "127.0.0.1" {
		cfg.serviceEndpoint = "http://127.0.0.1:" + cfg.port
	}
	return cfg
}

type service struct {
	db  *sql.DB
	cfg config
}

func (s *service) authorize(w http.ResponseWriter, r *http.Request) bool {
	if s.cfg.serviceToken == "" {
		http.Error(w, `{"error":"INTERNAL_SERVICE_TOKEN is not configured"}`, http.StatusServiceUnavailable)
		return false
	}
	provided := r.Header.Get("X-Internal-Service-Token")
	if len(provided) != len(s.cfg.serviceToken) ||
		subtle.ConstantTimeCompare([]byte(provided), []byte(s.cfg.serviceToken)) != 1 {
		http.Error(w, `{"error":"Unauthorized"}`, http.StatusUnauthorized)
		return false
	}
	return true
}

func (s *service) createUser(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(w, r) {
		return
	}
	var input struct {
		Username     string `json:"username"`
		PasswordHash string `json:"password_hash"`
	}
	if err := decodeJSON(w, r, &input); err != nil || input.Username == "" || input.PasswordHash == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "username and password_hash are required"})
		return
	}
	result, err := s.db.ExecContext(r.Context(),
		"INSERT INTO users (username, password_hash) VALUES (?, ?)",
		input.Username, input.PasswordHash)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unique") {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Username already exists"})
			return
		}
		log.Printf("database insert failed: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Database error"})
		return
	}
	id, _ := result.LastInsertId()
	writeJSON(w, http.StatusCreated, map[string]any{"status": "ok", "user_id": id})
}

func (s *service) getUser(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(w, r) {
		return
	}
	username := strings.TrimPrefix(r.URL.Path, "/db/users/")
	if username == "" || strings.Contains(username, "/") {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "User not found"})
		return
	}
	var user struct {
		ID           int64
		Username     string
		PasswordHash string
	}
	err := s.db.QueryRowContext(r.Context(),
		"SELECT id, username, password_hash FROM users WHERE username = ?", username).
		Scan(&user.ID, &user.Username, &user.PasswordHash)
	if errors.Is(err, sql.ErrNoRows) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "User not found"})
		return
	}
	if err != nil {
		log.Printf("database lookup failed: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Database error"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"user_id": user.ID, "username": user.Username, "password_hash": user.PasswordHash,
	})
}

func decodeJSON(w http.ResponseWriter, r *http.Request, destination any) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var extra any
	if decoder.Decode(&extra) == nil {
		return errors.New("multiple JSON values")
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func registerWithDNS(cfg config) error {
	if cfg.dnsURL == "" {
		return nil
	}
	body := strings.NewReader(`{"domain":"` + cfg.serviceDomain + `"}`)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.dnsURL+"/register", body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if cfg.serviceEndpoint != "" {
		req.Header.Set("X-Service-Endpoint", cfg.serviceEndpoint)
	}
	if cfg.dnsToken != "" {
		req.Header.Set("X-DNS-Service-Token", cfg.dnsToken)
	}
	response, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return errors.New("DNS registration returned " + strconv.Itoa(response.StatusCode))
	}
	return nil
}

func main() {
	cfg := loadConfig()
	if cfg.serviceToken == "" {
		log.Fatal("INTERNAL_SERVICE_TOKEN must be configured")
	}
	db, err := sql.Open("sqlite", cfg.database)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`
		PRAGMA busy_timeout = 5000;
		PRAGMA journal_mode = WAL;
		CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT NOT NULL UNIQUE,
			password_hash TEXT NOT NULL
		);`); err != nil {
		log.Fatal(err)
	}
	s := &service{db: db, cfg: cfg}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /db/users", s.createUser)
	mux.HandleFunc("GET /db/users/{username}", s.getUser)
	handler := rateLimit(maxBody(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = r.WithContext(r.Context())
		mux.ServeHTTP(w, r)
	})), 120, time.Minute)
	server := &http.Server{
		Addr: cfg.bindAddress + ":" + cfg.port, Handler: handler,
		ReadHeaderTimeout: 2 * time.Second, ReadTimeout: 5 * time.Second,
		WriteTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second,
	}
	if err := registerWithDNS(cfg); err != nil {
		log.Fatal(err)
	}
	log.Printf("acm-db listening on %s", server.Addr)
	log.Fatal(server.ListenAndServe())
}

func maxBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ContentLength > maxBodyBytes {
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func rateLimit(next http.Handler, limit int, window time.Duration) http.Handler {
	type bucket struct {
		count int
		reset time.Time
	}
	buckets := map[string]bucket{}
	var mu = make(chan struct{}, 1)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip, _, _ := net.SplitHostPort(r.RemoteAddr)
		if ip == "" {
			ip = r.RemoteAddr
		}
		now := time.Now()
		mu <- struct{}{}
		if len(buckets) >= 10000 {
			for key, value := range buckets {
				if now.After(value.reset) {
					delete(buckets, key)
				}
			}
			if len(buckets) >= 10000 {
				<-mu
				http.Error(w, "rate limiter busy", http.StatusServiceUnavailable)
				return
			}
		}
		current := buckets[ip]
		if now.After(current.reset) {
			current = bucket{reset: now.Add(window)}
		}
		current.count++
		buckets[ip] = current
		<-mu
		if current.count > limit {
			http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}
