package main

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"
)

type remoteForwarder struct {
	target   string
	listener net.Listener
}

type remoteForwarderRegistry struct {
	mu          sync.Mutex
	forwarders  map[int]remoteForwarder
	sourceRange *netip.Prefix
}

func newRemoteForwarderRegistry(sourceCIDR string) *remoteForwarderRegistry {
	registry := &remoteForwarderRegistry{forwarders: make(map[int]remoteForwarder)}
	if prefix, err := netip.ParsePrefix(strings.TrimSpace(sourceCIDR)); err == nil {
		masked := prefix.Masked()
		registry.sourceRange = &masked
	}
	return registry
}

func (r *remoteForwarderRegistry) Upsert(publicPort int, target string) error {
	if publicPort < 1024 || publicPort > 65535 {
		return fmt.Errorf("invalid public port %d", publicPort)
	}
	if err := validateWinboxTarget(target); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if current, ok := r.forwarders[publicPort]; ok {
		if current.target == target {
			return nil
		}
		_ = current.listener.Close()
		delete(r.forwarders, publicPort)
	}
	listener, err := net.Listen("tcp", ":"+strconv.Itoa(publicPort))
	if err != nil {
		return err
	}
	forwarder := remoteForwarder{target: target, listener: listener}
	r.forwarders[publicPort] = forwarder
	go r.serve(forwarder)
	return nil
}

func (r *remoteForwarderRegistry) Remove(publicPort int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if forwarder, ok := r.forwarders[publicPort]; ok {
		_ = forwarder.listener.Close()
		delete(r.forwarders, publicPort)
	}
}

func (r *remoteForwarderRegistry) Reconcile(desired map[int]string) error {
	for port, target := range desired {
		if err := r.Upsert(port, target); err != nil {
			return fmt.Errorf("listen on port %d: %w", port, err)
		}
	}
	r.mu.Lock()
	stale := make([]int, 0)
	for port := range r.forwarders {
		if _, ok := desired[port]; !ok {
			stale = append(stale, port)
		}
	}
	r.mu.Unlock()
	for _, port := range stale {
		r.Remove(port)
	}
	return nil
}

func (r *remoteForwarderRegistry) Close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for port, forwarder := range r.forwarders {
		_ = forwarder.listener.Close()
		delete(r.forwarders, port)
	}
}

func (r *remoteForwarderRegistry) serve(forwarder remoteForwarder) {
	for {
		client, err := forwarder.listener.Accept()
		if err != nil {
			return
		}
		if !r.sourceAllowed(client.RemoteAddr()) {
			_ = client.Close()
			continue
		}
		go proxyTCP(client, forwarder.target)
	}
}

func (r *remoteForwarderRegistry) sourceAllowed(address net.Addr) bool {
	if r.sourceRange == nil {
		return true
	}
	host, _, err := net.SplitHostPort(address.String())
	if err != nil {
		return false
	}
	addr, err := netip.ParseAddr(host)
	return err == nil && r.sourceRange.Contains(addr.Unmap())
}

func proxyTCP(client net.Conn, target string) {
	defer client.Close()
	upstream, err := net.DialTimeout("tcp", target, 8*time.Second)
	if err != nil {
		return
	}
	defer upstream.Close()
	done := make(chan struct{}, 2)
	copyConn := func(dst, src net.Conn) {
		_, _ = io.Copy(dst, src)
		if tcp, ok := dst.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		}
		done <- struct{}{}
	}
	go copyConn(upstream, client)
	go copyConn(client, upstream)
	<-done
}

func validateWinboxTarget(target string) error {
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return errors.New("invalid WinBox target")
	}
	addr, err := netip.ParseAddr(host)
	if err != nil || !addr.IsPrivate() {
		return errors.New("WinBox target must be a private WireGuard address")
	}
	if port != "8291" {
		return errors.New("WinBox target port must be 8291")
	}
	return nil
}
