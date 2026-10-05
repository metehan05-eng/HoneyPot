package services

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"github.com/metehan05-eng/sentinel-trap/internal/analysis"
	"github.com/metehan05-eng/sentinel-trap/internal/logger"
)

type RawTCPHoneypot struct {
	Port   string
	Logger *logger.Logger
}

func NewRawTCPHoneypot(port string, lg *logger.Logger) *RawTCPHoneypot {
	return &RawTCPHoneypot{Port: port, Logger: lg}
}

func (r *RawTCPHoneypot) Start() {
	listener, err := net.Listen("tcp", r.Port)
	if err != nil {
		log.Printf("Raw TCP port başlatılamadı %s: %v", r.Port, err)
		return
	}
	defer listener.Close()

	log.Printf("[*] Raw TCP Honeypot dinleniyor: %s", r.Port)
	for {
		conn, err := listener.Accept()
		if err != nil {
			continue
		}
		go r.handleConnection(conn)
	}
}

func (r *RawTCPHoneypot) handleConnection(conn net.Conn) {
	defer conn.Close()

	remoteIP := conn.RemoteAddr().String()
	if analysis.Default().IsBlocked(remoteIP) {
		return
	}
	banner := r.bannerForPort()
	_, _ = conn.Write([]byte(banner + "\r\n"))

	reader := bufio.NewReader(conn)
	for {
		if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
			return
		}
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		cmd := strings.TrimSpace(line)
		if cmd == "" {
			continue
		}
		r.Logger.Log(logger.Event{
			Service:  "RAW-TCP",
			RemoteIP: remoteIP,
			Payload:  cmd,
		})
		_, _ = conn.Write([]byte("unknown command\r\n"))
	}
}

func (r *RawTCPHoneypot) bannerForPort() string {
	switch {
	case strings.Contains(r.Port, ":21"):
		return "220 (Ubuntu) FTP server ready"
	case strings.Contains(r.Port, ":23"):
		return "Connected to fake telnet server"
	case strings.Contains(r.Port, ":3306"):
		return "5.7.39 MySQL Community Server"
	case strings.Contains(r.Port, ":6379"):
		return "+OK redis-server"
	default:
		return fmt.Sprintf("220 %s ready", r.Port)
	}
}
