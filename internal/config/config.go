package config

import (
	"os"

	"gopkg.in/yaml.v3"
)

type ServerConfig struct {
	Name string `yaml:"name"`
}

type ServiceConfig struct {
	Enabled bool     `yaml:"enabled"`
	Port    string   `yaml:"port"`
	Ports   []string `yaml:"ports"`
}

type ServicesConfig struct {
	SSH       ServiceConfig `yaml:"ssh"`
	HTTP      ServiceConfig `yaml:"http"`
	Dashboard ServiceConfig `yaml:"dashboard"`
	RawTCP    ServiceConfig `yaml:"raw_tcp"`
}

type LoggingConfig struct {
	FilePath string `yaml:"file_path"`
}

type StorageConfig struct {
	Enabled    bool   `yaml:"enabled"`
	Type       string `yaml:"type"`
	SQLitePath string `yaml:"sqlite_path"`
	MongoURI   string `yaml:"mongo_uri"`
	MongoDB    string `yaml:"mongo_db"`
	MongoTable string `yaml:"mongo_table"`
}

type SMTPConfig struct {
	Enabled  bool     `yaml:"enabled"`
	Host     string   `yaml:"host"`
	Port     int      `yaml:"port"`
	Username string   `yaml:"username"`
	Password string   `yaml:"password"`
	From     string   `yaml:"from"`
	To       []string `yaml:"to"`
}

type NotifierConfig struct {
	TelegramEnabled bool       `yaml:"telegram_enabled"`
	BotToken        string     `yaml:"bot_token"`
	ChatID          string     `yaml:"chat_id"`
	Email           SMTPConfig `yaml:"email"`
}

type AnalysisConfig struct {
	Threshold    int `yaml:"threshold"`
	WindowSec    int `yaml:"window_sec"`
	BlockMinutes int `yaml:"block_minutes"`
}

type Config struct {
	Server   ServerConfig   `yaml:"server"`
	Services ServicesConfig `yaml:"services"`
	Logging  LoggingConfig  `yaml:"logging"`
	Storage  StorageConfig  `yaml:"storage"`
	Notifier NotifierConfig `yaml:"notifier"`
	Analysis AnalysisConfig `yaml:"analysis"`
}

func LoadConfig(path string) (Config, error) {
	var cfg Config

	content, err := os.ReadFile(path)
	if err != nil {
		return cfg, err
	}

	if err := yaml.Unmarshal(content, &cfg); err != nil {
		return cfg, err
	}

	if cfg.Server.Name == "" {
		cfg.Server.Name = "Sentinel-Trap-Node-01"
	}
	if cfg.Logging.FilePath == "" {
		cfg.Logging.FilePath = "logs/honeypot.json"
	}
	if cfg.Services.SSH.Port == "" {
		cfg.Services.SSH.Port = ":2222"
	}
	if cfg.Services.HTTP.Port == "" {
		cfg.Services.HTTP.Port = ":8080"
	}
	if cfg.Services.Dashboard.Port == "" {
		cfg.Services.Dashboard.Port = ":8081"
	}
	if len(cfg.Services.RawTCP.Ports) == 0 {
		cfg.Services.RawTCP.Ports = []string{":21", ":23", ":3306", ":6379"}
	}
	if cfg.Storage.Type == "" {
		cfg.Storage.Type = "sqlite"
	}
	if cfg.Storage.SQLitePath == "" {
		cfg.Storage.SQLitePath = "logs/honeypot.db"
	}
	if cfg.Storage.MongoTable == "" {
		cfg.Storage.MongoTable = "honeypot_events"
	}
	if cfg.Analysis.Threshold == 0 {
		cfg.Analysis.Threshold = 5
	}
	if cfg.Analysis.WindowSec == 0 {
		cfg.Analysis.WindowSec = 300
	}
	if cfg.Analysis.BlockMinutes == 0 {
		cfg.Analysis.BlockMinutes = 60
	}

	return cfg, nil
}
