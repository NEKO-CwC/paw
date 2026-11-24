package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/crypto/ssh"
)

type settings struct {
	publicURL      string
	publicHost     string
	httpAddr       string
	relayAddr      string
	accessAddr     string
	relayPort      uint32
	accessPort     uint32
	dataDir        string
	assetsDir      string
	adminPassword  string
	defaultMinutes int
}

func env(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func readSettings() (settings, error) {
	cfg := settings{
		publicURL: strings.TrimRight(env("PAW_PUBLIC_URL", "https://windows-support.284072.xyz"), "/"),
		httpAddr:  env("PAW_HTTP_ADDR", ":8080"), relayAddr: env("PAW_RELAY_ADDR", ":49222"),
		accessAddr: env("PAW_ACCESS_ADDR", ":49223"), dataDir: env("PAW_DATA_DIR", "/data"),
		assetsDir: env("PAW_ASSETS_DIR", "/assets"),
	}
	endpoint, err := url.Parse(cfg.publicURL)
	if err != nil || endpoint.Scheme != "https" || endpoint.Hostname() == "" ||
		endpoint.User != nil || endpoint.Path != "" || endpoint.RawQuery != "" || endpoint.Fragment != "" {
		return cfg, errors.New("PAW_PUBLIC_URL must be an HTTPS origin")
	}
	cfg.publicHost = env("PAW_SSH_HOST", endpoint.Hostname())
	if !validHost(cfg.publicHost) {
		return cfg, errors.New("invalid PAW_SSH_HOST")
	}
	for _, binding := range []struct {
		key, addr string
		port      *uint32
	}{
		{"PAW_RELAY_PORT", cfg.relayAddr, &cfg.relayPort},
		{"PAW_ACCESS_PORT", cfg.accessAddr, &cfg.accessPort},
	} {
		_, fallback, err := net.SplitHostPort(binding.addr)
		if err != nil {
			return cfg, err
		}
		value, err := strconv.Atoi(env(binding.key, fallback))
		if err != nil || value < 1 || value > 65535 {
			return cfg, fmt.Errorf("invalid %s", binding.key)
		}
		*binding.port = uint32(value)
	}
	cfg.defaultMinutes, err = strconv.Atoi(env("PAW_DEFAULT_MINUTES", "240"))
	if err != nil || cfg.defaultMinutes < 1 || cfg.defaultMinutes > maxMinutes {
		return cfg, errors.New("invalid PAW_DEFAULT_MINUTES")
	}
	password, err := os.ReadFile(env("PAW_ADMIN_PASSWORD_FILE", "/data/admin-password"))
	if err != nil {
		return cfg, err
	}
	cfg.adminPassword = strings.TrimRight(string(password), "\r\n")
	if len(cfg.adminPassword) == 0 || len(cfg.adminPassword) > 256 {
		return cfg, errors.New("invalid administrator password")
	}
	return cfg, nil
}

var hostPattern = regexp.MustCompile("^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$")
var userPattern = regexp.MustCompile("^[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}$")
var fingerprintPattern = regexp.MustCompile("^SHA256:[A-Za-z0-9+/]{43}$")

func validHost(name string) bool {
	return net.ParseIP(name) != nil || hostPattern.MatchString(name)
}

type proxySettings struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	User     string `json:"user"`
	Password string `json:"password,omitempty"`
	HostKey  string `json:"hostKey"`
}

func (p proxySettings) validate() error {
	if p.Host == "" {
		return nil
	}
	if !validHost(p.Host) || p.Port < 1 || p.Port > 65535 || !userPattern.MatchString(p.User) ||
		!fingerprintPattern.MatchString(p.HostKey) || len(p.Password) > 256 ||
		strings.ContainsAny(p.Password, "\r\n\x00") {
		return errors.New("请填写有效的 SSH 主机、端口、用户名和 SHA256 主机指纹")
	}
	return nil
}

func atomicFile(path string, data []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".paw-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	_, err = f.Write(data)
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Rename(f.Name(), path)
}

func loadProxy(path string) (proxySettings, error) {
	var proxy proxySettings
	body, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return proxy, nil
	}
	if err != nil {
		return proxy, err
	}
	if err := json.Unmarshal(body, &proxy); err != nil {
		return proxy, err
	}
	return proxy, proxy.validate()
}

func randomToken(n int) (string, error) {
	data := make([]byte, n)
	_, err := rand.Read(data)
	return base64.RawURLEncoding.EncodeToString(data), err
}

func makeKey(comment string) (ssh.Signer, []byte, error) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	block, err := ssh.MarshalPrivateKey(private, comment)
	if err != nil {
		return nil, nil, err
	}
	signer, err := ssh.NewSignerFromKey(private)
	return signer, pem.EncodeToMemory(block), err
}
