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

type FakeService struct {
	Name    string
	Port    string
	Banner  string
	Logger  *logger.Logger
	Prompt  string
	Handler func(string) string
}

func NewFTPHoneypot(port string, lg *logger.Logger) *FakeService {
	return &FakeService{Name: "FTP", Port: port, Banner: "220 (Ubuntu) FTP server ready", Prompt: "ftp> ", Logger: lg,
		Handler: func(cmd string) string {
			if strings.Contains(cmd, "USER") || strings.Contains(cmd, "PASS") {
				return "230 Login successful\r\n"
			}
			return "200 Command okay\r\n"
		}}
}

func NewTelnetHoneypot(port string, lg *logger.Logger) *FakeService {
	return &FakeService{Name: "Telnet", Port: port, Banner: "Connected to fake telnet server", Prompt: "# ", Logger: lg,
		Handler: func(cmd string) string {
			switch {
			case cmd == "" || cmd == " ":
				return ""
			case cmd == "whoami":
				return "root\r\n"
			default:
				return "unknown command\r\n"
			}
		}}
}

func NewMySQLHoneypot(port string, lg *logger.Logger) *FakeService {
	return &FakeService{Name: "MySQL", Port: port, Banner: "5.7.39 MySQL Community Server", Prompt: "mysql> ", Logger: lg,
		Handler: func(cmd string) string {
			switch {
			case strings.Contains(cmd, "SELECT"):
				return "+--------------------+\r\n"
			case strings.Contains(cmd, "mysql_native_password"):
				return "Authentication plugin not supported\r\n"
			default:
				return "ERROR 1064 (42000): You have an error in your SQL syntax\r\n"
			}
		}}
}

func NewRedisHoneypot(port string, lg *logger.Logger) *FakeService {
	return &FakeService{Name: "Redis", Port: port, Banner: "+OK redis-server", Prompt: ":6379> ", Logger: lg,
		Handler: func(cmd string) string {
			switch {
			case strings.Contains(cmd, "PING"):
				return "+PONG\r\n"
			case strings.Contains(cmd, "INFO"):
				return "+redis_version:7.0.0\r\n"
			default:
				return "-ERR unknown command\r\n"
			}
		}}
}

func (f *FakeService) Start() {
	listener, err := net.Listen("tcp", f.Port)
	if err != nil {
		log.Printf("Fake service %s başlatılamadı %s: %v", f.Name, f.Port, err)
		return
	}
	defer listener.Close()

	log.Printf("[*] %s Honeypot dinleniyor: %s", f.Name, f.Port)
	for {
		conn, err := listener.Accept()
		if err != nil {
			continue
		}
		go f.handleConnection(conn)
	}
}

func (f *FakeService) handleConnection(conn net.Conn) {
	defer conn.Close()

	remoteIP := conn.RemoteAddr().String()
	if analysis.Default().IsBlocked(remoteIP) {
		return
	}

	_, _ = conn.Write([]byte(f.Banner + "\r\n"))
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
		if f.Logger != nil {
			f.Logger.Log(logger.Event{Service: f.Name + "-Service", RemoteIP: remoteIP, Payload: cmd})
		}
		if f.Handler != nil {
			_, _ = conn.Write([]byte(f.Handler(cmd)))
		}
	}
}

func (f *FakeService) startNamedService() {
	_ = fmt.Sprintf("%s", f.Name)
}
