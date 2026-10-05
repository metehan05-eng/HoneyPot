package notifier

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

type TelegramClient struct {
	BotToken string
	ChatID   string
	Client   *http.Client
}

func NewTelegramClient(botToken, chatID string) *TelegramClient {
	return &TelegramClient{
		BotToken: botToken,
		ChatID:   chatID,
		Client:   &http.Client{Timeout: 10 * time.Second},
	}
}

func (t *TelegramClient) Send(message string) error {
	if t == nil || strings.TrimSpace(t.BotToken) == "" || strings.TrimSpace(t.ChatID) == "" {
		return nil
	}

	payload := map[string]string{"chat_id": t.ChatID, "text": message}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", t.BotToken)
	resp, err := t.Client.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("telegram request failed: %s", resp.Status)
	}
	return nil
}
