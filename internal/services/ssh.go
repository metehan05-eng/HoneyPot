package services

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"time"

	"github.com/metehan05-eng/sentinel-trap/internal/analysis"
	"github.com/metehan05-eng/sentinel-trap/internal/logger"
	"golang.org/x/crypto/ssh"
)

type SSHHoneypot struct {
	Port   string
	Logger *logger.Logger
}

func NewSSHHoneypot(port string, lg *logger.Logger) *SSHHoneypot {
	return &SSHHoneypot{Port: port, Logger: lg}
}

func (s *SSHHoneypot) Start() {
	config := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			s.Logger.Log(logger.Event{
				Service:  "SSH-Auth",
				RemoteIP: c.RemoteAddr().String(),
				Username: c.User(),
				Password: string(pass),
			})
			return nil, nil
		},
		PublicKeyCallback: func(c ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			s.Logger.Log(logger.Event{
				Service:  "SSH-PublicKey",
				RemoteIP: c.RemoteAddr().String(),
				Username: c.User(),
				Payload:  key.Type() + " key attempt",
			})
			return nil, nil
		},
	}

	privateKey, err := generateHostKey()
	if err != nil {
		log.Printf("SSH Host key oluşturulamadı: %v", err)
		return
	}
	config.AddHostKey(privateKey)

	listener, err := net.Listen("tcp", s.Port)
	if err != nil {
		log.Printf("SSH Port hatası %s: %v", s.Port, err)
		return
	}
	defer listener.Close()

	log.Printf("[*] SSH Honeypot dinleniyor: %s", s.Port)
	for {
		nConn, err := listener.Accept()
		if err != nil {
			continue
		}
		go s.handleConnection(nConn, config)
	}
}

func (s *SSHHoneypot) handleConnection(nConn net.Conn, config *ssh.ServerConfig) {
	defer nConn.Close()

	if analysis.Default().IsBlocked(nConn.RemoteAddr().String()) {
		return
	}

	serverConn, chans, reqs, err := ssh.NewServerConn(nConn, config)
	if err != nil {
		return
	}
	defer serverConn.Close()

	go ssh.DiscardRequests(reqs)

	for newChannel := range chans {
		if newChannel.ChannelType() != "session" {
			newChannel.Reject(ssh.UnknownChannelType, "Bilinmeyen kanal")
			continue
		}

		channel, requests, err := newChannel.Accept()
		if err != nil {
			return
		}

		go func(in <-chan *ssh.Request) {
			for req := range in {
				switch req.Type {
				case "shell", "pty-req", "exec":
					req.Reply(true, nil)
				default:
					req.Reply(false, nil)
				}
			}
		}(requests)

		s.handleFakeShell(channel, nConn.RemoteAddr().String(), serverConn.User())
		_ = channel.Close()
	}
}

func (s *SSHHoneypot) handleFakeShell(term io.ReadWriter, remoteIP, user string) {
	term.Write([]byte("Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-88-generic x86_64)\r\n\r\nroot@srv-prod-01:~# "))

	buf := make([]byte, 1024)
	for {
		n, err := term.Read(buf)
		if err != nil {
			return
		}
		cmd := sanitizeCommand(string(buf[:n]))
		if cmd == "" {
			term.Write([]byte("root@srv-prod-01:~# "))
			continue
		}

		s.Logger.Log(logger.Event{
			Service:  "SSH-Shell",
			RemoteIP: remoteIP,
			Username: user,
			Payload:  cmd,
		})

		var resp string
		switch {
		case cmd == "whoami":
			resp = "root\r\n"
		case cmd == "id":
			resp = "uid=0(root) gid=0(root) groups=0(root)\r\n"
		case cmd == "uname -a":
			resp = "Linux srv-prod-01 5.15.0-88-generic #1 SMP Thu Oct 5 12:00:00 UTC 2023 x86_64 GNU/Linux\r\n"
		case cmd == "ls" || cmd == "ls -la":
			resp = "total 12\r\ndrwx------ 2 root root 4096 Oct 6 12:00 .\r\n-rw-r--r-- 1 root root 220 Oct 6 12:00 .bashrc\r\n-rw-r--r-- 1 root root 807 Oct 6 12:00 database_backup.sql\r\n"
		case cmd == "cat /etc/passwd":
			resp = "root:x:0:0:root:/root:/bin/bash\r\nadmin:x:1000:1000:admin:/home/admin:/bin/bash\r\n"
		case cmd == "sudo -l":
			resp = "Matching Defaults entries for root on srv-prod-01:\r\nUser root may run sudo /bin/bash as ANYUSER\r\n"
		case cmd == "exit":
			return
		case strings.Contains(cmd, "curl") || strings.Contains(cmd, "wget"):
			resp = "curl: (7) Failed to connect to localhost port 80: Connection refused\r\n"
		default:
			resp = fmt.Sprintf("bash: %s: command not found\r\n", cmd)
		}

		term.Write([]byte(resp + "root@srv-prod-01:~# "))
	}
}

func generateHostKey() (ssh.Signer, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	return ssh.NewSignerFromKey(privateKey)
}

func sanitizeCommand(raw string) string {
	cmd := strings.TrimSpace(raw)
	cmd = strings.Trim(cmd, "\x00")
	cmd = strings.ReplaceAll(cmd, "\r", "")
	cmd = strings.ReplaceAll(cmd, "\n", "")
	return cmd
}

func init() {
	_ = time.Second
}
