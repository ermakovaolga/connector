package main

import (
	"net/netip"
	"strings"
	"sync"
)

// Policy решает, через какой outbound отправить соединение.
type Policy struct {
	cfg *Config
}

// MatchDomain возвращает правило для домена (или nil).
func (p *Policy) MatchDomain(name string) *RuleConfig {
	name = strings.Trim(strings.ToLower(name), ".")
	for i, r := range p.cfg.Rules {
		for _, s := range r.DomainSuffix {
			if name == s || strings.HasSuffix(name, "."+s) {
				return &p.cfg.Rules[i]
			}
		}
	}
	return nil
}

// MatchIP возвращает имя outbound для IP-адреса.
func (p *Policy) MatchIP(ip netip.Addr) string {
	for _, r := range p.cfg.Rules {
		for _, s := range r.IPCIDR {
			if netip.MustParsePrefix(s).Contains(ip) {
				return r.Outbound
			}
		}
	}
	return p.cfg.Default
}

// FakeIPPool выдаёт адреса из fake_ip_range и помнит, что за ними стоит.
type FakeIPPool struct {
	mu      sync.Mutex
	prefix  netip.Prefix
	next    netip.Addr
	byReal  map[string]netip.Addr // outbound|realIP -> fake
	entries map[netip.Addr]FakeEntry
}

type FakeEntry struct {
	Domain   string
	Real     netip.Addr
	Outbound string
}

func NewFakeIPPool(prefix netip.Prefix) *FakeIPPool {
	p := &FakeIPPool{
		prefix:  prefix.Masked(),
		byReal:  map[string]netip.Addr{},
		entries: map[netip.Addr]FakeEntry{},
	}
	// Начинаем с .1.0, чтобы не пересекаться с адресами TUN/DNS в .0.x.
	a := p.prefix.Addr().As4()
	a[2] = 1
	p.next = netip.AddrFrom4(a)
	return p
}

func (p *FakeIPPool) Get(e FakeEntry) netip.Addr {
	p.mu.Lock()
	defer p.mu.Unlock()
	key := e.Outbound + "|" + e.Real.String()
	if f, ok := p.byReal[key]; ok {
		p.entries[f] = e // обновим домен на последний запрошенный
		return f
	}
	f := p.next
	p.next = p.next.Next()
	if !p.prefix.Contains(p.next) {
		a := p.prefix.Addr().As4()
		a[2] = 1
		p.next = netip.AddrFrom4(a) // PoC: просто по кругу
	}
	p.byReal[key] = f
	p.entries[f] = e
	return f
}

func (p *FakeIPPool) Lookup(fake netip.Addr) (FakeEntry, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	e, ok := p.entries[fake]
	return e, ok
}
