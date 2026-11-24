package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"text/template"
	"time"

	"golang.org/x/crypto/ssh"
)

//go:embed web/* client/*.ps1
var resources embed.FS

const maxMinutes = 10080

type window struct {
	id, token, password string
	until               time.Time
	relayPublic         ssh.PublicKey
	relayPrivate        []byte
	relay               *ssh.ServerConn
	listener            net.Listener
	hostKey             string
}

type application struct {
	cfg      settings
	mu       sync.Mutex
	current  *window
	timer    *time.Timer
	proxy    proxySettings
	hostKey  ssh.PublicKey
	assets   map[string]string
	authGate chan struct{}
	failures map[string]failedLogin
}

type failedLogin struct {
	count int
	until time.Time
}

type windowStatus struct {
	Active         bool      `json:"active"`
	Connected      bool      `json:"connected"`
	Until          time.Time `json:"until,omitempty"`
	URL            string    `json:"url,omitempty"`
	SSHCommand     string    `json:"sshCommand,omitempty"`
	Password       string    `json:"password,omitempty"`
	Fingerprint    string    `json:"fingerprint,omitempty"`
	KnownHost      string    `json:"knownHost,omitempty"`
	DefaultMinutes int       `json:"defaultMinutes"`
	MaxMinutes     int       `json:"maxMinutes"`
}

func sameSecret(left, right string) bool {
	a, b := sha256.Sum256([]byte(left)), sha256.Sum256([]byte(right))
	return subtle.ConstantTimeCompare(a[:], b[:]) == 1
}

func main() {
	cfg, err := readSettings()
	if err != nil {
		log.Fatal(err)
	}
	if err := os.MkdirAll(cfg.dataDir, 0700); err != nil {
		log.Fatal(err)
	}
	proxy, err := loadProxy(filepath.Join(cfg.dataDir, "proxy.json"))
	if err != nil {
		log.Fatal(err)
	}
	hostKey, err := loadRelayKey(cfg.dataDir)
	if err != nil {
		log.Fatal(err)
	}
	digests := map[string]string{}
	for _, name := range []string{"OpenSSH-Win64.zip", "plink.exe"} {
		digest, err := fileDigest(filepath.Join(cfg.assetsDir, name))
		if err != nil {
			log.Fatal(err)
		}
		digests[name] = digest
	}
	app := &application{cfg: cfg, proxy: proxy, hostKey: hostKey.PublicKey(),
		assets: digests, failures: make(map[string]failedLogin), authGate: make(chan struct{}, 1)}
	listener, err := net.Listen("tcp", cfg.relayAddr)
	if err != nil {
		log.Fatal(err)
	}
	go app.serveRelay(listener, hostKey)
	log.Printf("web %s, SSH relay %s, operator %s", cfg.httpAddr, cfg.relayAddr, cfg.accessAddr)
	server := http.Server{Addr: cfg.httpAddr, Handler: app.routes(),
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 20 * time.Second, WriteTimeout: 40 * time.Second,
		IdleTimeout: 45 * time.Second, MaxHeaderBytes: 16 << 10}
	log.Fatal(server.ListenAndServe())
}

func loadRelayKey(dir string) (ssh.Signer, error) {
	path := filepath.Join(dir, "relay-key")
	data, err := os.ReadFile(path)
	if err == nil {
		return ssh.ParsePrivateKey(data)
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	signer, private, err := makeKey("paw-relay")
	if err != nil {
		return nil, err
	}
	return signer, atomicFile(path, private)
}

func fileDigest(path string) (string, error) {
	input, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer input.Close()
	h := sha256.New()
	_, err = io.Copy(h, input)
	return strings.ToUpper(hex.EncodeToString(h.Sum(nil))), err
}

func (app *application) closeWindow() {
	if app.timer != nil {
		app.timer.Stop()
	}
	if current := app.current; current != nil {
		if current.listener != nil {
			current.listener.Close()
		}
		if current.relay != nil {
			current.relay.Close()
		}
		app.current = nil
	}
}

func (app *application) setExpiry(current *window) {
	if app.timer != nil {
		app.timer.Stop()
	}
	app.timer = time.AfterFunc(time.Until(current.until), func() {
		app.mu.Lock()
		defer app.mu.Unlock()
		if app.current == current && !time.Now().Before(current.until) {
			app.closeWindow()
		}
	})
}

func (app *application) liveWindow() *window {
	if app.current != nil && !time.Now().Before(app.current.until) {
		app.closeWindow()
	}
	return app.current
}

func (app *application) status(private bool) windowStatus {
	status := windowStatus{DefaultMinutes: app.cfg.defaultMinutes, MaxMinutes: maxMinutes}
	current := app.liveWindow()
	if current == nil {
		return status
	}
	status.Active = true
	status.Connected = current.listener != nil && current.hostKey != ""
	status.Until = current.until
	if private {
		status.URL = app.cfg.publicURL + "/assist/" + current.token
		status.SSHCommand = fmt.Sprintf("ssh -p %d paw%s@%s", app.cfg.accessPort, current.id, app.cfg.publicHost)
		status.Password = current.password
		if current.hostKey != "" {
			key, _, _, _, _ := ssh.ParseAuthorizedKey([]byte(current.hostKey))
			status.Fingerprint = ssh.FingerprintSHA256(key)
			status.KnownHost = fmt.Sprintf("[%s]:%d %s", app.cfg.publicHost, app.cfg.accessPort, current.hostKey)
		}
	}
	return status
}

func jsonReply(w http.ResponseWriter, code int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(value)
}

func fail(w http.ResponseWriter, code int, message string) {
	jsonReply(w, code, map[string]string{"error": message})
}

func readJSON(w http.ResponseWriter, r *http.Request, data any) bool {
	defer r.Body.Close()
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192))
	d.DisallowUnknownFields()
	if d.Decode(data) != nil || d.Decode(new(any)) != io.EOF {
		fail(w, http.StatusBadRequest, "请求格式错误")
		return false
	}
	return true
}

func (app *application) authenticate(w http.ResponseWriter, r *http.Request) bool {
	client, _, _ := net.SplitHostPort(r.RemoteAddr)
	if ip := net.ParseIP(r.Header.Get("X-Real-IP")); ip != nil {
		client = ip.String()
	}
	app.authGate <- struct{}{}
	defer func() { <-app.authGate }()
	now := time.Now()
	attempt := app.failures[client]
	if now.Before(attempt.until) && attempt.count >= 8 {
		fail(w, http.StatusTooManyRequests, "请稍后再试")
		return false
	}
	user, password, valid := r.BasicAuth()
	if valid && user == "admin" && sameSecret(password, app.cfg.adminPassword) {
		delete(app.failures, client)
		return true
	}
	for ip, entry := range app.failures {
		if !now.Before(entry.until) {
			delete(app.failures, ip)
		}
	}
	if !now.Before(attempt.until) {
		attempt = failedLogin{until: now.Add(time.Minute)}
	}
	if len(app.failures) < 4096 {
		attempt.count++
		app.failures[client] = attempt
	}
	fail(w, http.StatusUnauthorized, "管理员密码错误")
	return false
}

func (app *application) admin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Header.Get("Origin") != app.cfg.publicURL {
		fail(w, http.StatusForbidden, "请求来源无效")
		return
	}
	if !app.authenticate(w, r) {
		return
	}
	app.mu.Lock()
	defer app.mu.Unlock()
	if r.Method == http.MethodGet {
		proxy := app.proxy
		proxy.Password = ""
		jsonReply(w, http.StatusOK, map[string]any{"window": app.status(true), "proxy": proxy,
			"hasProxyPassword": app.proxy.Password != ""})
		return
	}
	var action struct {
		Action  string        `json:"action"`
		Minutes int           `json:"minutes,omitempty"`
		Proxy   proxySettings `json:"proxy,omitempty"`
	}
	if !readJSON(w, r, &action) {
		return
	}
	current := app.liveWindow()
	switch action.Action {
	case "open", "extend":
		if action.Minutes < 1 || action.Minutes > maxMinutes {
			fail(w, 400, "请输入有效的窗口时长")
			return
		}
		if action.Action == "open" && current != nil || action.Action == "extend" && current == nil {
			fail(w, 409, "接入窗口状态已变化")
			return
		}
		duration := time.Duration(action.Minutes) * time.Minute
		if current == nil {
			var err error
			current, err = newWindow(time.Now().Add(duration))
			if err != nil {
				fail(w, 500, "无法生成临时凭据")
				return
			}
			app.current = current
		} else {
			current.until = current.until.Add(duration)
		}
		app.setExpiry(current)
	case "close":
		app.closeWindow()
	case "proxy":
		proxy := action.Proxy
		if proxy.Host == "" {
			proxy = proxySettings{}
		} else if proxy.Password == "" && proxy.Host == app.proxy.Host &&
			proxy.Port == app.proxy.Port && proxy.User == app.proxy.User && proxy.HostKey == app.proxy.HostKey {
			proxy.Password = app.proxy.Password
		}
		if err := proxy.validate(); err != nil {
			fail(w, 400, err.Error())
			return
		}
		data, err := json.Marshal(proxy)
		if err != nil || atomicFile(filepath.Join(app.cfg.dataDir, "proxy.json"), data) != nil {
			fail(w, 500, "无法保存下载代理")
			return
		}
		app.proxy = proxy
	default:
		fail(w, 400, "操作无效")
		return
	}
	jsonReply(w, http.StatusOK, app.status(true))
}

func newWindow(until time.Time) (*window, error) {
	id := make([]byte, 6)
	if _, err := rand.Read(id); err != nil {
		return nil, err
	}
	token, err := randomToken(24)
	if err != nil {
		return nil, err
	}
	password, err := randomToken(18)
	if err != nil {
		return nil, err
	}
	signer, key, err := makeKey("paw-session")
	if err != nil {
		return nil, err
	}
	return &window{id: hex.EncodeToString(id), token: token, password: password + "Aa7!",
		until: until, relayPublic: signer.PublicKey(), relayPrivate: key}, nil
}

var bootstrapTemplate = template.Must(template.ParseFS(resources, "client/connect.ps1"))
var cleanupTemplate = template.Must(template.ParseFS(resources, "client/cleanup.ps1"))
var sessionID = regexp.MustCompile("^[a-f0-9]{12}$")

func (app *application) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", servePage)
	mux.HandleFunc("GET /assist/{token}", servePage)
	mux.HandleFunc("GET /app.js", func(w http.ResponseWriter, r *http.Request) {
		serveAsset(w, "web/app.js", "text/javascript; charset=utf-8")
	})
	mux.HandleFunc("GET /style.css", func(w http.ResponseWriter, r *http.Request) {
		serveAsset(w, "web/style.css", "text/css; charset=utf-8")
	})
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok\n")) })
	mux.HandleFunc("GET /api/status", func(w http.ResponseWriter, r *http.Request) {
		app.mu.Lock()
		defer app.mu.Unlock()
		jsonReply(w, 200, app.status(false))
	})
	mux.HandleFunc("GET /api/admin", app.admin)
	mux.HandleFunc("POST /api/admin", app.admin)
	mux.HandleFunc("GET /session/{token}/bootstrap.ps1", app.bootstrap)
	mux.HandleFunc("GET /session/{token}/lease", app.lease)
	mux.HandleFunc("POST /session/{token}/host-key", app.reportHostKey)
	mux.HandleFunc("GET /session/{token}/asset/{name}", app.download)
	mux.HandleFunc("GET /cleanup/{id}", func(w http.ResponseWriter, r *http.Request) {
		if !sessionID.MatchString(r.PathValue("id")) {
			http.NotFound(w, r)
			return
		}
		renderScript(w, cleanupTemplate, r.PathValue("id"))
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'")
		mux.ServeHTTP(w, r)
	})
}

func servePage(w http.ResponseWriter, r *http.Request) {
	serveAsset(w, "web/index.html", "text/html; charset=utf-8")
}

func serveAsset(w http.ResponseWriter, path, contentType string) {
	data, err := resources.ReadFile(path)
	if err != nil {
		w.WriteHeader(500)
		return
	}
	w.Header().Set("Content-Type", contentType)
	w.Write(data)
}

func (app *application) forToken(token string) *window {
	current := app.liveWindow()
	if current == nil || !sameSecret(current.token, token) {
		return nil
	}
	return current
}

func (app *application) bootstrap(w http.ResponseWriter, r *http.Request) {
	app.mu.Lock()
	current := app.forToken(r.PathValue("token"))
	if current == nil {
		app.mu.Unlock()
		fail(w, 410, "接入窗口已关闭或链接无效")
		return
	}
	endpoint := app.cfg.publicURL + "/session/" + current.token
	host := app.cfg.publicHost
	known := host
	if app.cfg.relayPort != 22 {
		known = "[" + host + "]:" + strconv.Itoa(int(app.cfg.relayPort))
	}
	cfg := map[string]any{
		"id": current.id, "until": current.until, "password": current.password,
		"relayHost": host, "relayPort": app.cfg.relayPort, "accessPort": app.cfg.accessPort,
		"relayKey": string(current.relayPrivate), "knownHost": known + " " + strings.TrimSpace(string(ssh.MarshalAuthorizedKey(app.hostKey))),
		"endpoint": endpoint, "cleanup": app.cfg.publicURL + "/cleanup/" + current.id,
		"archiveHash": app.assets["OpenSSH-Win64.zip"], "plinkHash": app.assets["plink.exe"], "proxy": app.proxy,
	}
	app.mu.Unlock()
	data, err := json.Marshal(cfg)
	if err != nil {
		fail(w, 500, "无法生成安装命令")
		return
	}
	renderScript(w, bootstrapTemplate, base64.StdEncoding.EncodeToString(data))
}

func renderScript(w http.ResponseWriter, script *template.Template, data string) {
	var output bytes.Buffer
	if err := script.Execute(&output, data); err != nil {
		fail(w, 500, "脚本渲染失败")
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write(output.Bytes())
}

func (app *application) lease(w http.ResponseWriter, r *http.Request) {
	app.mu.Lock()
	defer app.mu.Unlock()
	current := app.forToken(r.PathValue("token"))
	if current == nil {
		fail(w, 410, "接入窗口已关闭")
		return
	}
	jsonReply(w, 200, map[string]any{"until": current.until, "id": current.id})
}

func (app *application) reportHostKey(w http.ResponseWriter, r *http.Request) {
	var report struct {
		Key string `json:"key"`
	}
	if !readJSON(w, r, &report) {
		return
	}
	key, _, options, rest, err := ssh.ParseAuthorizedKey([]byte(report.Key))
	if err != nil || key.Type() != ssh.KeyAlgoED25519 || len(options) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		fail(w, 400, "无效的 Windows SSH 主机密钥")
		return
	}
	app.mu.Lock()
	defer app.mu.Unlock()
	current := app.forToken(r.PathValue("token"))
	if current == nil {
		fail(w, 410, "接入窗口已关闭")
		return
	}
	if current.relay != nil {
		fail(w, 409, "已有 Windows 客户端连接")
		return
	}
	current.hostKey = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
	w.WriteHeader(204)
}

func (app *application) download(w http.ResponseWriter, r *http.Request) {
	app.mu.Lock()
	allowed := app.forToken(r.PathValue("token")) != nil
	app.mu.Unlock()
	if !allowed {
		fail(w, 410, "接入窗口已关闭")
		return
	}
	name := r.PathValue("name")
	if _, ok := app.assets[name]; !ok {
		http.NotFound(w, r)
		return
	}
	http.ServeFile(w, r, filepath.Join(app.cfg.assetsDir, name))
}
