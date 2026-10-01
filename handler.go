package main

import (
	"context"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/xjasonlyu/tun2socks/v2/core/adapter"
)

// Handler получает TCP/UDP-потоки, которые gVisor-стек собрал из пакетов TUN.
type Handler struct {
	policy    *Policy
	pool      *FakeIPPool
	outbounds map[string]*Outbound
	dns       *DNSServer
	dnsAddr   netip.Addr
}

// route: куда на самом деле подключаться и через какой outbound.
func (h *Handler) route(dst netip.Addr) (real netip.Addr, outbound, label string, ok bool) {
	if e, found := h.pool.Lookup(dst); found {
		return e.Real, e.Outbound, e.Domain + " -> " + e.Real.String(), true
	}
	if h.pool.prefix.Contains(dst) {
		return dst, "", "", false // fake IP без записи (агент перезапускался?)
	}
	return dst, h.policy.MatchIP(dst), dst.String(), true
}

func (h *Handler) HandleTCP(c adapter.TCPConn) {
	defer c.Close()
	id := c.ID()
	dst, _ := netip.AddrFromSlice(id.LocalAddress.AsSlice())
	port := id.LocalPort

	real, obName, label, ok := h.route(dst)
	if !ok {
		logf("tcp  %s:%d unknown fake IP, drop", dst, port)
		return
	}
	ob := h.outbounds[obName]
	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	rc, ifc, err := ob.DialContext(ctx, "tcp4", net.JoinHostPort(real.String(), strconv.Itoa(int(port))))
	cancel()
	if err != nil {
		logf("tcp  %s:%d (%s) -> %s: FAIL %v", dst, port, label, obName, err)
		return
	}
	defer rc.Close()
	logf("tcp  %s:%d (%s) -> %s[%s] connected in %s", dst, port, label, obName, ifc.Name, time.Since(start).Round(time.Millisecond))
	up, down := relay(c, rc)
	logf("tcp  %s:%d closed: up %dB, down %dB", dst, port, up, down)
}

func relay(a, b net.Conn) (ab, ba int64) {
	var wg sync.WaitGroup
	wg.Add(2)
	cp := func(dst, src net.Conn, n *int64) {
		defer wg.Done()
		*n, _ = io.Copy(dst, src)
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		} else {
			_ = dst.SetReadDeadline(time.Now())
		}
	}
	go cp(b, a, &ab)
	go cp(a, b, &ba)
	wg.Wait()
	return
}

func (h *Handler) HandleUDP(c adapter.UDPConn) {
	defer c.Close()
	id := c.ID()
	dst, _ := netip.AddrFromSlice(id.LocalAddress.AsSlice())
	port := id.LocalPort

	if dst == h.dnsAddr && port == 53 {
		h.serveDNS(c)
		return
	}

	real, obName, label, ok := h.route(dst)
	if !ok {
		return
	}
	pc, ifc, err := h.outbounds[obName].ListenPacket()
	if err != nil {
		logf("udp  %s:%d (%s) -> %s: FAIL %v", dst, port, label, obName, err)
		return
	}
	defer pc.Close()
	logf("udp  %s:%d (%s) -> %s[%s]", dst, port, label, obName, ifc.Name)
	raddr := &net.UDPAddr{IP: real.AsSlice(), Port: int(port)}

	const idle = 60 * time.Second
	go func() {
		buf := make([]byte, 65535)
		for {
			_ = pc.SetReadDeadline(time.Now().Add(idle))
			n, _, err := pc.ReadFrom(buf)
			if err != nil {
				_ = c.SetReadDeadline(time.Now()) // разбудить второй цикл
				return
			}
			if _, err := c.Write(buf[:n]); err != nil {
				return
			}
		}
	}()
	buf := make([]byte, 65535)
	for {
		_ = c.SetReadDeadline(time.Now().Add(idle))
		n, err := c.Read(buf)
		if err != nil {
			_ = pc.SetReadDeadline(time.Now())
			return
		}
		if _, err := pc.WriteTo(buf[:n], raddr); err != nil {
			return
		}
	}
}

func (h *Handler) serveDNS(c adapter.UDPConn) {
	buf := make([]byte, 4096)
	for {
		_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
		n, err := c.Read(buf)
		if err != nil {
			return
		}
		if resp, err := h.dns.Handle(buf[:n]); err == nil {
			_, _ = c.Write(resp)
		}
	}
}
