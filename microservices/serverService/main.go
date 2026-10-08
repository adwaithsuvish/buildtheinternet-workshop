package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const maxBodyBytes = 16 * 1024

type config struct {
	bindAddress, port, dnsURL, dbURL, dbPort, serviceDomain, serviceToken string
	dnsToken                                                              string
	allowedDBHosts                                                        map[string]bool
	secureCookies                                                         bool
}

func env(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}

func loadConfig() config {
	hosts := map[string]bool{}
	for _, host := range strings.Split(env("DB_ALLOWED_HOSTS", "127.0.0.1,localhost"), ",") {
		if host = strings.TrimSpace(host); host != "" {
			hosts[host] = true
		}
	}
	return config{
		bindAddress: env("BIND_ADDRESS", "127.0.0.1"),
		port:        env("PORT", "5002"), dnsURL: strings.TrimRight(os.Getenv("DNS_URL"), "/"),
		dbURL: strings.TrimRight(os.Getenv("DB_URL"), "/"), dbPort: env("DB_PORT", "5001"),
		serviceDomain:  env("SERVICE_DOMAIN", "acm-server"),
		serviceToken:   env("INTERNAL_SERVICE_TOKEN", ""),
		dnsToken:       env("DNS_SERVICE_TOKEN", ""),
		allowedDBHosts: hosts,
		secureCookies:  strings.EqualFold(env("SESSION_COOKIE_SECURE", "true"), "true"),
	}
}

type session struct {
	userID   int64
	username string
	expires  time.Time
}
type service struct {
	cfg      config
	client   *http.Client
	mu       sync.RWMutex
	sessions map[string]session
	dbURL    string
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
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

func validCredentials(username, password string) bool {
	return len(username) > 0 && len(username) <= 128 && len(password) > 0 && len(password) <= 256
}

func (s *service) register(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if decodeJSON(w, r, &input) != nil || !validCredentials(strings.TrimSpace(input.Username), input.Password) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "username and password are required"})
		return
	}
	username := strings.TrimSpace(input.Username)
	hash, err := bcrypt.GenerateFromPassword([]byte(input.Password), bcrypt.DefaultCost)
	if err != nil {
		log.Printf("password hashing failed: %v", err)
		writeJSON(w, 500, map[string]string{"error": "Internal server error"})
		return
	}
	response, err := s.databaseRequest(r.Context(), http.MethodPost, "/db/users",
		map[string]string{"username": username, "password_hash": string(hash)})
	if err != nil {
		writeJSON(w, 502, map[string]string{"error": "Database service unavailable"})
		return
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusBadRequest {
		writeJSON(w, 400, map[string]string{"error": "Username already exists"})
		return
	}
	if response.StatusCode != http.StatusCreated {
		writeJSON(w, 502, map[string]string{"error": "Database service error"})
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"status": "ok", "message": "User registered successfully"})
}

func (s *service) login(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if decodeJSON(w, r, &input) != nil || !validCredentials(strings.TrimSpace(input.Username), input.Password) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "Invalid username or password"})
		return
	}
	username := strings.TrimSpace(input.Username)
	response, err := s.databaseRequest(r.Context(), http.MethodGet, "/db/users/"+url.PathEscape(username), nil)
	if err != nil {
		writeJSON(w, 502, map[string]string{"error": "Database service unavailable"})
		return
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNotFound {
		writeJSON(w, 401, map[string]string{"error": "Invalid username or password"})
		return
	}
	if response.StatusCode != http.StatusOK {
		writeJSON(w, 502, map[string]string{"error": "Database service error"})
		return
	}
	var user struct {
		UserID       int64  `json:"user_id"`
		Username     string `json:"username"`
		PasswordHash string `json:"password_hash"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, response.Body, maxBodyBytes)).Decode(&user); err != nil {
		writeJSON(w, 502, map[string]string{"error": "Invalid database response"})
		return
	}
	if bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(input.Password)) != nil {
		writeJSON(w, 401, map[string]string{"error": "Invalid username or password"})
		return
	}
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		writeJSON(w, 500, map[string]string{"error": "Internal server error"})
		return
	}
	token := base64.RawURLEncoding.EncodeToString(tokenBytes)
	s.mu.Lock()
	if len(s.sessions) >= 100000 {
		for existingToken, current := range s.sessions {
			if time.Now().After(current.expires) {
				delete(s.sessions, existingToken)
			}
		}
	}
	if len(s.sessions) >= 100000 {
		s.mu.Unlock()
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "Session capacity reached"})
		return
	}
	s.sessions[token] = session{userID: user.UserID, username: username, expires: time.Now().Add(12 * time.Hour)}
	s.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: "session_id", Value: token, Path: "/", HttpOnly: true, Secure: s.cfg.secureCookies, SameSite: http.SameSiteLaxMode, MaxAge: 43200})
	writeJSON(w, 200, map[string]string{"status": "ok", "message": "Login successful"})
}

func (s *service) whoami(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session_id")
	if err != nil {
		writeJSON(w, 401, map[string]string{"error": "Unauthorized - Invalid or missing session cookie"})
		return
	}
	s.mu.Lock()
	current, ok := s.sessions[cookie.Value]
	if ok && time.Now().After(current.expires) {
		delete(s.sessions, cookie.Value)
		ok = false
	}
	s.mu.Unlock()
	if !ok || time.Now().After(current.expires) {
		writeJSON(w, 401, map[string]string{"error": "Unauthorized - Invalid or missing session cookie"})
		return
	}
	writeJSON(w, 200, map[string]any{"status": "ok", "user_id": current.userID, "username": current.username})
}

func (s *service) databaseServiceURL(ctx context.Context) (string, error) {
	s.mu.RLock()
	if s.dbURL != "" {
		value := s.dbURL
		s.mu.RUnlock()
		return value, nil
	}
	s.mu.RUnlock()
	if s.cfg.dbURL != "" {
		return validateDBURL(s.cfg.dbURL, s.cfg.allowedDBHosts)
	}
	if s.cfg.dnsURL == "" {
		return "", errors.New("DNS_URL is not configured")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.cfg.dnsURL+"/lookup?domain=acm-db", nil)
	if err != nil {
		return "", err
	}
	if s.cfg.dnsToken != "" {
		req.Header.Set("X-DNS-Service-Token", s.cfg.dnsToken)
	}
	response, err := s.client.Do(req)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return "", fmt.Errorf("DNS lookup returned %d", response.StatusCode)
	}
	var result struct {
		Destination string `json:"destination"`
	}
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		return "", err
	}
	destination := result.Destination
	if !strings.Contains(destination, "://") {
		destination = "http://" + destination + ":" + s.cfg.dbPort
	}
	value, err := validateDBURL(destination, s.cfg.allowedDBHosts)
	if err != nil {
		return "", err
	}
	s.mu.Lock()
	s.dbURL = value
	s.mu.Unlock()
	return value, nil
}

func validateDBURL(raw string, allowed map[string]bool) (string, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "http" && parsed.Scheme != "https" || parsed.User != nil || parsed.Path != "" && parsed.Path != "/" || parsed.Hostname() == "" || !allowed[parsed.Hostname()] {
		return "", errors.New("database destination is not allowlisted")
	}
	return strings.TrimRight(parsed.String(), "/"), nil
}

func (s *service) databaseRequest(ctx context.Context, method, path string, payload any) (*http.Response, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	base, err := s.databaseServiceURL(ctx)
	if err != nil {
		return nil, err
	}
	var body *strings.Reader
	if payload == nil {
		body = strings.NewReader("")
	} else {
		encoded, err := json.Marshal(payload)
		if err != nil {
			return nil, err
		}
		body = strings.NewReader(string(encoded))
	}
	req, err := http.NewRequestWithContext(ctx, method, base+path, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Internal-Service-Token", s.cfg.serviceToken)
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return s.client.Do(req)
}

func registerWithDNS(cfg config) error {
	if cfg.dnsURL == "" {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.dnsURL+"/register", strings.NewReader(`{"domain":"`+cfg.serviceDomain+`"}`))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if cfg.dnsToken != "" {
		req.Header.Set("X-DNS-Service-Token", cfg.dnsToken)
	}
	response, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("DNS registration returned %d", response.StatusCode)
	}
	return nil
}

func main() {
	cfg := loadConfig()
	if cfg.serviceToken == "" {
		log.Fatal("INTERNAL_SERVICE_TOKEN must be configured")
	}
	s := &service{cfg: cfg, client: &http.Client{Timeout: 4 * time.Second}, sessions: make(map[string]session)}
	go s.removeExpiredSessions()
	mux := http.NewServeMux()
	mux.HandleFunc("POST /register", s.register)
	mux.HandleFunc("POST /login", s.login)
	mux.HandleFunc("GET /whoami", s.whoami)
	handler := rateLimit(maxBody(mux), 120, time.Minute)
	server := &http.Server{Addr: cfg.bindAddress + ":" + cfg.port, Handler: handler, ReadHeaderTimeout: 2 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second}
	if err := registerWithDNS(cfg); err != nil {
		log.Fatal(err)
	}

	log.Printf("acm-server listening on %s", server.Addr)
	log.Fatal(server.ListenAndServe())
}

func (s *service) removeExpiredSessions() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()
	for now := range ticker.C {
		s.mu.Lock()
		for token, current := range s.sessions {
			if now.After(current.expires) {
				delete(s.sessions, token)
			}
		}
		s.mu.Unlock()
	}
}

func maxBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ContentLength > maxBodyBytes {
			http.Error(w, "request body too large", 413)
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
	var mu sync.Mutex
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip, _, _ := net.SplitHostPort(r.RemoteAddr)
		if ip == "" {
			ip = r.RemoteAddr
		}
		now := time.Now()
		mu.Lock()
		if len(buckets) >= 10000 {
			for key, value := range buckets {
				if now.After(value.reset) {
					delete(buckets, key)
				}
			}
			if len(buckets) >= 10000 {
				mu.Unlock()
				http.Error(w, "rate limiter busy", 503)
				return
			}
		}
		b := buckets[ip]
		if now.After(b.reset) {
			b = bucket{reset: now.Add(window)}
		}
		b.count++
		buckets[ip] = b
		mu.Unlock()
		if b.count > limit {
			http.Error(w, "rate limit exceeded", 429)
			return
		}
		next.ServeHTTP(w, r)
	})
}
