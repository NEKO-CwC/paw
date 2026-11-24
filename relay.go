package main

import (
	"errors"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

type forwardRequest struct {
	Host string
	Port uint32
}

type forwardedConnection struct {
	Host       string
	Port       uint32
	OriginHost string
	OriginPort uint32
}

func (app *application) serveRelay(listener net.Listener, hostKey ssh.Signer) {
	config := &ssh.ServerConfig{
		MaxAuthTries: 2,
		PublicKeyCallback: func(meta ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			app.mu.Lock()
			defer app.mu.Unlock()
			current := app.current
			if meta.User() != "paw" || current == nil || !time.Now().Before(current.until) ||
				!sameSecret(string(current.relayPublic.Marshal()), string(key.Marshal())) {
				return nil, errors.New("invalid or expired tunnel identity")
			}
			return &ssh.Permissions{Extensions: map[string]string{"session": current.id}}, nil
		},
	}
	config.AddHostKey(hostKey)
	admission := make(chan struct{}, 24)
	for {
		raw, err := listener.Accept()
		if err != nil {
			return
		}
		select {
		case admission <- struct{}{}:
			go func() {
				defer func() { <-admission }()
				app.relayConnection(raw, config)
			}()
		default:
			raw.Close()
		}
	}
}

func (app *application) relayConnection(raw net.Conn, config *ssh.ServerConfig) {
	defer raw.Close()
	raw.SetDeadline(time.Now().Add(12 * time.Second))
	conn, channels, requests, err := ssh.NewServerConn(raw, config)
	if err != nil {
		return
	}
	defer conn.Close()
	raw.SetDeadline(time.Time{})
	go func() {
		for channel := range channels {
			channel.Reject(ssh.Prohibited, "relay accepts reverse forwarding only")
		}
	}()

	app.mu.Lock()
	current := app.current
	if current == nil || current.id != conn.Permissions.Extensions["session"] ||
		!time.Now().Before(current.until) || current.relay != nil {
		app.mu.Unlock()
		return
	}
	current.relay = conn
	app.mu.Unlock()
	defer func() {
		app.mu.Lock()
		defer app.mu.Unlock()
		if current.listener != nil {
			current.listener.Close()
			current.listener = nil
		}
		current.relay = nil
	}()

	for request := range requests {
		switch request.Type {
		case "tcpip-forward":
			app.startForward(current, conn, request)
		case "keepalive@openssh.com":
			request.Reply(true, nil)
		default:
			request.Reply(false, nil)
		}
	}
}

func (app *application) startForward(current *window, conn *ssh.ServerConn, request *ssh.Request) {
	var target forwardRequest
	if ssh.Unmarshal(request.Payload, &target) != nil ||
		target.Host != "0.0.0.0" || target.Port != app.cfg.accessPort {
		request.Reply(false, nil)
		return
	}
	app.mu.Lock()
	defer app.mu.Unlock()
	if app.current != current || !time.Now().Before(current.until) || current.listener != nil {
		request.Reply(false, nil)
		return
	}
	listener, err := net.Listen("tcp", app.cfg.accessAddr)
	if err != nil {
		log.Printf("operator listener: %v", err)
		request.Reply(false, nil)
		return
	}
	current.listener = listener
	if err := request.Reply(true, nil); err != nil {
		listener.Close()
		current.listener = nil
		return
	}
	go acceptOperators(listener, conn, target)
}

func acceptOperators(listener net.Listener, tunnel *ssh.ServerConn, target forwardRequest) {
	active := make(chan struct{}, 16)
	for {
		client, err := listener.Accept()
		if err != nil {
			return
		}
		select {
		case active <- struct{}{}:
			go func() {
				defer func() { <-active }()
				forwardOperator(client, tunnel, target)
			}()
		default:
			client.Close()
		}
	}
}

func forwardOperator(client net.Conn, tunnel *ssh.ServerConn, target forwardRequest) {
	defer client.Close()
	origin, ok := client.RemoteAddr().(*net.TCPAddr)
	if !ok {
		return
	}
	message := forwardedConnection{target.Host, target.Port, origin.IP.String(), uint32(origin.Port)}
	channel, requests, err := tunnel.OpenChannel("forwarded-tcpip", ssh.Marshal(message))
	if err != nil {
		return
	}
	defer channel.Close()
	go ssh.DiscardRequests(requests)
	var streams sync.WaitGroup
	streams.Go(func() {
		io.Copy(channel, client)
		channel.CloseWrite()
	})
	io.Copy(client, channel)
	client.Close()
	streams.Wait()
}
