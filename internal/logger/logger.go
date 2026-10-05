package logger

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type Event struct {
	Timestamp string `json:"timestamp"`
	Server    string `json:"server,omitempty"`
	Service   string `json:"service"`
	RemoteIP  string `json:"remote_ip,omitempty"`
	Payload   string `json:"payload,omitempty"`
	Username  string `json:"username,omitempty"`
	Password  string `json:"password,omitempty"`
	UserAgent string `json:"user_agent,omitempty"`
}

type EventHandler func(Event)

type Logger struct {
	file     *os.File
	mu       sync.Mutex
	handlers []EventHandler
}

func NewLogger(filePath string, handlers ...EventHandler) (*Logger, error) {
	if filePath == "" {
		filePath = "honeypot.json"
	}

	if err := os.MkdirAll(filepath.Dir(filePath), 0o755); err != nil && filepath.Dir(filePath) != "." {
		return nil, err
	}

	file, err := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o666)
	if err != nil {
		return nil, err
	}

	return &Logger{file: file, handlers: handlers}, nil
}

func (l *Logger) AddHandler(handler EventHandler) {
	if handler == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.handlers = append(l.handlers, handler)
}

func (l *Logger) Log(event Event) {
	if l == nil || l.file == nil {
		return
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	event.Timestamp = time.Now().UTC().Format(time.RFC3339)
	data, err := json.Marshal(event)
	if err != nil {
		data = []byte(fmt.Sprintf("{\"service\":%q,\"error\":%q}", event.Service, err.Error()))
	}

	fmt.Println(string(data))
	_, _ = l.file.Write(append(data, '\n'))

	for _, handler := range l.handlers {
		if handler != nil {
			handler(event)
		}
	}
}

func (l *Logger) Close() error {
	if l == nil || l.file == nil {
		return nil
	}
	return l.file.Close()
}
