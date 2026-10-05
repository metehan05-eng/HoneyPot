package services

import (
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/metehan05-eng/sentinel-trap/internal/analysis"
	"github.com/metehan05-eng/sentinel-trap/internal/logger"
)

type HTTPHoneypot struct {
	Port   string
	Logger *logger.Logger
}

func NewHTTPHoneypot(port string, lg *logger.Logger) *HTTPHoneypot {
	return &HTTPHoneypot{Port: port, Logger: lg}
}

func (h *HTTPHoneypot) Start() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if analysis.Default().IsBlocked(r.RemoteAddr) {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		h.Logger.Log(logger.Event{
			Service:   "HTTP-Web",
			RemoteIP:  r.RemoteAddr,
			Payload:   fmt.Sprintf("%s %s", r.Method, r.URL.Path),
			UserAgent: r.UserAgent(),
		})

		if r.Method == http.MethodPost {
			if err := r.ParseForm(); err == nil {
				username := r.FormValue("user")
				password := r.FormValue("pass")
				if username != "" || password != "" {
					h.Logger.Log(logger.Event{
						Service:  "HTTP-Login",
						RemoteIP: r.RemoteAddr,
						Username: username,
						Password: password,
					})
				}
			}
		}

		w.Header().Set("Server", "Apache/2.4.52 (Ubuntu)")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, `<html><body><h2>Control Panel Login</h2><form method="POST" action="/login"><input type="text" name="user" placeholder="Username"/><input type="password" name="pass" placeholder="Password"/><input type="submit" value="Login"/></form></body></html>`)
	})

	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err == nil {
			h.Logger.Log(logger.Event{
				Service:  "HTTP-Login",
				RemoteIP: r.RemoteAddr,
				Username: r.FormValue("user"),
				Password: r.FormValue("pass"),
			})
		}
		w.Header().Set("Server", "Apache/2.4.52 (Ubuntu)")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("401 Unauthorized - Invalid credentials"))
	})

	server := &http.Server{
		Addr:              h.Port,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       15 * time.Second,
	}

	log.Printf("[*] HTTP Honeypot dinleniyor: %s", h.Port)
	if err := server.ListenAndServe(); err != nil && !strings.Contains(err.Error(), "Server closed") {
		log.Printf("HTTP Honeypot hata: %v", err)
	}
}
