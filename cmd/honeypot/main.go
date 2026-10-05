package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/metehan05-eng/sentinel-trap/internal/analysis"
	"github.com/metehan05-eng/sentinel-trap/internal/config"
	"github.com/metehan05-eng/sentinel-trap/internal/dashboard"
	"github.com/metehan05-eng/sentinel-trap/internal/logger"
	"github.com/metehan05-eng/sentinel-trap/internal/notifier"
	"github.com/metehan05-eng/sentinel-trap/internal/services"
	"github.com/metehan05-eng/sentinel-trap/internal/storage"
)

func main() {
	log.Println("=== Sentinel-Trap Honeypot Başlatılıyor ===")

	cfgPath := filepath.Join("configs", "config.yaml")
	if _, err := os.Stat(cfgPath); err != nil {
		cfgPath = filepath.Join(".", "configs", "config.yaml")
	}

	cfg, err := config.LoadConfig(cfgPath)
	if err != nil {
		log.Fatalf("Yapılandırma dosyası okunamadı: %v", err)
	}

	var handlers []logger.EventHandler
	attackAnalyzer := analysis.NewAnalyzer(cfg.Analysis)
	var store storage.Store

	handlers = append(handlers, func(event logger.Event) {
		attackAnalyzer.Record(event)
	})

	if cfg.Storage.Enabled {
		store, err = newStorage(cfg)
		if err != nil {
			log.Printf("Depolama başlatılamadı: %v", err)
		} else {
			handlers = append(handlers, func(event logger.Event) {
				if err := store.Save(event); err != nil {
					log.Printf("Event kaydı başarısız: %v", err)
				}
			})
		}
	}

	if store == nil && cfg.Storage.Enabled {
		store, err = storage.NewSQLiteStore(cfg.Storage.SQLitePath)
		if err != nil {
			log.Printf("SQLite yedek depolama açılamadı: %v", err)
		}
	}

	if cfg.Notifier.TelegramEnabled {
		tg := notifier.NewTelegramClient(cfg.Notifier.BotToken, cfg.Notifier.ChatID)
		handlers = append(handlers, func(event logger.Event) {
			msg := formatNotification(event)
			if err := tg.Send(msg); err != nil {
				log.Printf("Telegram bildirimi gönderilemedi: %v", err)
			}
		})
	}

	if cfg.Notifier.Email.Enabled {
		handlers = append(handlers, func(event logger.Event) {
			if err := notifier.SendEmail(cfg.Notifier.Email, event); err != nil {
				log.Printf("E-posta bildirimi gönderilemedi: %v", err)
			}
		})
	}

	lg, err := logger.NewLogger(cfg.Logging.FilePath, handlers...)
	if err != nil {
		log.Fatalf("Logger başlatılamadı: %v", err)
	}
	defer lg.Close()

	if cfg.Services.SSH.Enabled {
		go services.NewSSHHoneypot(cfg.Services.SSH.Port, lg).Start()
	}
	if cfg.Services.HTTP.Enabled {
		go services.NewHTTPHoneypot(cfg.Services.HTTP.Port, lg).Start()
	}
	if cfg.Services.RawTCP.Enabled {
		for _, port := range cfg.Services.RawTCP.Ports {
			go services.NewRawTCPHoneypot(port, lg).Start()
		}
	}
	if cfg.Services.Dashboard.Enabled {
		go dashboard.NewDashboard(cfg.Services.Dashboard.Port, store, attackAnalyzer, strings.ToLower(cfg.Storage.Type)).Start()
	}

	log.Printf("[*] IP analizörü aktif: threshold=%d window=%ds block=%dm", cfg.Analysis.Threshold, cfg.Analysis.WindowSec, cfg.Analysis.BlockMinutes)
	select {}
}

func newStorage(cfg config.Config) (storage.Store, error) {
	switch strings.ToLower(cfg.Storage.Type) {
	case "mongo", "mongodb":
		return storage.NewMongoStore(cfg.Storage.MongoURI, cfg.Storage.MongoDB, cfg.Storage.MongoTable)
	case "sqlite", "":
		return storage.NewSQLiteStore(cfg.Storage.SQLitePath)
	default:
		return storage.NewSQLiteStore(cfg.Storage.SQLitePath)
	}
}

func formatNotification(event logger.Event) string {
	parts := []string{event.Service, event.RemoteIP}
	if event.Username != "" {
		parts = append(parts, "user="+event.Username)
	}
	if event.Password != "" {
		parts = append(parts, "pass="+event.Password)
	}
	if event.Payload != "" {
		parts = append(parts, "payload="+event.Payload)
	}
	return fmt.Sprintf("[Sentinel-Trap] %s", strings.Join(parts, " | "))
}
