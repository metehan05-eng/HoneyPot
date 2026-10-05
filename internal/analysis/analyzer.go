package analysis

import (
	"net"
	"sync"
	"time"

	"github.com/metehan05-eng/sentinel-trap/internal/config"
	"github.com/metehan05-eng/sentinel-trap/internal/logger"
)

type Analyzer struct {
	mu           sync.Mutex
	window       time.Duration
	threshold    int
	blockMinutes time.Duration
	counts       map[string]int
	seen         map[string]time.Time
	blocked      map[string]time.Time
}

var defaultAnalyzer *Analyzer

func NewAnalyzer(cfg config.AnalysisConfig) *Analyzer {
	if cfg.WindowSec <= 0 {
		cfg.WindowSec = 300
	}
	if cfg.Threshold <= 0 {
		cfg.Threshold = 5
	}
	if cfg.BlockMinutes <= 0 {
		cfg.BlockMinutes = 60
	}

	a := &Analyzer{
		window:       time.Duration(cfg.WindowSec) * time.Second,
		threshold:    cfg.Threshold,
		blockMinutes: time.Duration(cfg.BlockMinutes) * time.Minute,
		counts:       make(map[string]int),
		seen:         make(map[string]time.Time),
		blocked:      make(map[string]time.Time),
	}
	defaultAnalyzer = a
	return a
}

func Default() *Analyzer {
	if defaultAnalyzer == nil {
		return NewAnalyzer(config.AnalysisConfig{Threshold: 5, WindowSec: 300, BlockMinutes: 60})
	}
	return defaultAnalyzer
}

func Configure(cfg config.AnalysisConfig) *Analyzer {
	return NewAnalyzer(cfg)
}

func (a *Analyzer) Record(event logger.Event) bool {
	if a == nil || event.RemoteIP == "" {
		return false
	}
	ip := normalizeIP(event.RemoteIP)
	if ip == "" {
		return false
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	if now := time.Now(); now.Sub(a.seen[ip]) > a.window {
		a.counts[ip] = 0
		a.seen[ip] = now
	}
	if until, ok := a.blocked[ip]; ok && time.Now().Before(until) {
		return true
	}
	if until, ok := a.blocked[ip]; ok && !time.Now().Before(until) {
		delete(a.blocked, ip)
	}

	a.counts[ip]++
	a.seen[ip] = time.Now()
	if a.counts[ip] >= a.threshold {
		a.blocked[ip] = time.Now().Add(a.blockMinutes)
		return true
	}
	return false
}

func (a *Analyzer) IsBlocked(ip string) bool {
	if a == nil {
		return false
	}
	ip = normalizeIP(ip)
	if ip == "" {
		return false
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	if until, ok := a.blocked[ip]; ok {
		if time.Now().Before(until) {
			return true
		}
		delete(a.blocked, ip)
	}
	return false
}

func (a *Analyzer) BlockedIPs() []string {
	if a == nil {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	ips := make([]string, 0, len(a.blocked))
	for ip, until := range a.blocked {
		if time.Now().Before(until) {
			ips = append(ips, ip)
		}
	}
	return ips
}

func normalizeIP(raw string) string {
	if raw == "" {
		return ""
	}
	host, _, err := net.SplitHostPort(raw)
	if err == nil {
		return host
	}
	return raw
}
