package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfig(t *testing.T) {
	tempDir := t.TempDir()
	cfgPath := filepath.Join(tempDir, "config.yaml")

	content := `server:
  name: "Trap-Node"
services:
  ssh:
    enabled: true
    port: ":2222"
  http:
    enabled: true
    port: ":8080"
logging:
  file_path: "logs/honeypot.json"
notifier:
  telegram_enabled: false
  bot_token: "token"
  chat_id: "chat"
`

	if err := os.WriteFile(cfgPath, []byte(content), 0o600); err != nil {
		t.Fatalf("config file write failed: %v", err)
	}

	cfg, err := LoadConfig(cfgPath)
	if err != nil {
		t.Fatalf("LoadConfig returned error: %v", err)
	}

	if cfg.Server.Name != "Trap-Node" {
		t.Fatalf("unexpected server name: %s", cfg.Server.Name)
	}
	if cfg.Services.SSH.Port != ":2222" {
		t.Fatalf("unexpected ssh port: %s", cfg.Services.SSH.Port)
	}
	if cfg.Logging.FilePath != "logs/honeypot.json" {
		t.Fatalf("unexpected log path: %s", cfg.Logging.FilePath)
	}
}
