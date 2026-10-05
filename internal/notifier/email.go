package notifier

import (
	"fmt"
	"net/smtp"
	"strings"

	"github.com/metehan05-eng/sentinel-trap/internal/config"
	"github.com/metehan05-eng/sentinel-trap/internal/logger"
)

func SendEmail(cfg config.SMTPConfig, event logger.Event) error {
	if !cfg.Enabled || strings.TrimSpace(cfg.Host) == "" || len(cfg.To) == 0 {
		return nil
	}
	if cfg.Port == 0 {
		cfg.Port = 587
	}
	message := fmt.Sprintf("Subject: Sentinel-Trap Alert\r\nTo: %s\r\nFrom: %s\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\nService: %s\nRemoteIP: %s\nUsername: %s\nPassword: %s\nPayload: %s\n",
		strings.Join(cfg.To, ", "),
		cfg.From,
		event.Service,
		event.RemoteIP,
		event.Username,
		event.Password,
		event.Payload,
	)
	addr := fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)
	auth := smtp.PlainAuth("", cfg.Username, cfg.Password, cfg.Host)
	return smtp.SendMail(addr, auth, cfg.From, cfg.To, []byte(message))
}
