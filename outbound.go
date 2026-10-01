package main

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/xjasonlyu/tun2socks/v2/dialer"
)

// Outbound — "выход" политики: сокеты, привязанные к конкретному интерфейсу
// (IP_BOUND_IF на macOS, IP_UNICAST_IF на Windows). Так трафик идёт в нужный
// VPN независимо от того, кто сейчас владеет default-маршрутом.
type Outbound struct {
	Name string
	cfg  OutboundConfig
	tun  string // имя нашего TUN, его никогда не выбираем

	// manage: агент работает с правами root и может ставить scoped default.
	manage bool
	undo   func()

	mu       sync.Mutex
	iface    *net.Interface
	resolved time.Time
}

func NewOutbound(name string, cfg OutboundConfig, tunName string) *Outbound {
	return &Outbound{Name: name, cfg: cfg, tun: tunName}
}

// Close убирает scoped default, если ставили.
func (o *Outbound) Close() {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.undo != nil {
		o.undo()
		o.undo = nil
	}
}

// Interface находит интерфейс (с кешем на 10 секунд: FortiClient при
// переподключении может получить другой utunN).
func (o *Outbound) Interface() (*net.Interface, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.iface != nil && time.Since(o.resolved) < 10*time.Second {
		return o.iface, nil
	}
	name := o.cfg.Interface
	if name == "" || name == "auto" {
		var err error
		if o.cfg.DetectBy != "" {
			name, err = detectInterfaceFor(o.cfg.DetectBy, o.tun)
		} else {
			name, err = detectPhysicalInterface()
		}
		if err != nil {
			return nil, fmt.Errorf("outbound %s: %w", o.Name, err)
		}
	}
	ifc, err := net.InterfaceByName(name)
	if err != nil {
		return nil, fmt.Errorf("outbound %s: %w", o.Name, err)
	}
	if o.iface == nil || o.iface.Name != ifc.Name {
		logf("outbound %-6s -> %s (index %d)", o.Name, ifc.Name, ifc.Index)
		if o.manage && o.cfg.ScopedDefault {
			// FortiClient переподключился на другой utunN: старый маршрут
			// исчез вместе с интерфейсом, ставим на новый.
			if o.undo != nil {
				o.undo()
			}
			if o.undo, err = addScopedDefault(ifc.Name); err != nil {
				logf("WARN %v", err)
			}
		}
	}
	o.iface, o.resolved = ifc, time.Now()
	return ifc, nil
}

func (o *Outbound) dialer() (*dialer.Dialer, *net.Interface, error) {
	ifc, err := o.Interface()
	if err != nil {
		return nil, nil, err
	}
	return dialer.New(dialer.WithBindToInterface(ifc)), ifc, nil
}

func (o *Outbound) DialContext(ctx context.Context, network, addr string) (net.Conn, *net.Interface, error) {
	d, ifc, err := o.dialer()
	if err != nil {
		return nil, nil, err
	}
	c, err := d.DialContext(ctx, network, addr)
	if err != nil {
		o.invalidate()
	}
	return c, ifc, err
}

func (o *Outbound) ListenPacket() (net.PacketConn, *net.Interface, error) {
	d, ifc, err := o.dialer()
	if err != nil {
		return nil, nil, err
	}
	pc, err := d.ListenPacket("udp4", "0.0.0.0:0")
	return pc, ifc, err
}

func (o *Outbound) invalidate() {
	o.mu.Lock()
	o.resolved = time.Time{}
	o.mu.Unlock()
}
