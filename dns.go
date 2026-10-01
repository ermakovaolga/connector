package main

import (
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/miekg/dns"
)

// DNSServer отвечает на запросы, пришедшие в TUN на dns_address.
// Для доменов из правил: спрашивает upstream (например 10.32.1.3) через
// outbound правила и отдаёт клиенту fake IP, за которым помнит реальный адрес
// и outbound. Так маршруты FortiClient на 10.32.x вообще не трогаются.
type DNSServer struct {
	policy    *Policy
	pool      *FakeIPPool
	outbounds map[string]*Outbound
}

func (s *DNSServer) Handle(req []byte) ([]byte, error) {
	var q dns.Msg
	if err := q.Unpack(req); err != nil {
		return nil, err
	}
	resp := new(dns.Msg)
	resp.SetReply(&q)
	resp.RecursionAvailable = true
	if len(q.Question) != 1 {
		resp.Rcode = dns.RcodeFormatError
		return resp.Pack()
	}
	qq := q.Question[0]
	rule := s.policy.MatchDomain(qq.Name)
	if rule == nil || len(rule.DNS) == 0 {
		// Сюда попадают только домены, для которых мы прописали
		// /etc/resolver (NRPT на Windows), так что это неожиданно.
		logf("dns  %s %s -> no rule, REFUSED", dns.TypeToString[qq.Qtype], qq.Name)
		resp.Rcode = dns.RcodeRefused
		return resp.Pack()
	}
	if qq.Qtype != dns.TypeA {
		// PoC только IPv4: на AAAA/прочее отвечаем пустым NOERROR.
		return resp.Pack()
	}

	ob := s.outbounds[rule.Outbound]
	var (
		up     *dns.Msg
		ifc    *net.Interface
		err    error
		server string
	)
	for _, server = range rule.DNS {
		up, ifc, err = s.exchange(ob, &q, server)
		if err == nil && up.Rcode == dns.RcodeSuccess {
			break
		}
		if err == nil {
			err = fmt.Errorf("rcode %s", dns.RcodeToString[up.Rcode])
		}
		logf("dns  A %s -> upstream %s via %s: %v", qq.Name, server, rule.Outbound, err)
	}
	if up == nil {
		resp.Rcode = dns.RcodeServerFailure
		return resp.Pack()
	}
	resp.Rcode = up.Rcode
	for _, rr := range up.Answer {
		a, ok := rr.(*dns.A)
		if !ok {
			continue // CNAME и т.п. опускаем: клиенту нужен только A
		}
		real, _ := netip.AddrFromSlice(a.A.To4())
		fake := s.pool.Get(FakeEntry{Domain: trimDot(qq.Name), Real: real, Outbound: rule.Outbound})
		resp.Answer = append(resp.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: qq.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 10},
			A:   net.IP(fake.AsSlice()),
		})
		logf("dns  A %s -> %s (upstream %s via %s[%s]) => fake %s", trimDot(qq.Name), real, server, rule.Outbound, ifc.Name, fake)
	}
	return resp.Pack()
}

func (s *DNSServer) exchange(ob *Outbound, q *dns.Msg, server string) (*dns.Msg, *net.Interface, error) {
	pc, ifc, err := ob.ListenPacket()
	if err != nil {
		return nil, nil, err
	}
	defer pc.Close()
	raddr, err := net.ResolveUDPAddr("udp4", net.JoinHostPort(server, "53"))
	if err != nil {
		return nil, ifc, err
	}
	m := q.Copy()
	m.Id = dns.Id()
	b, _ := m.Pack()
	buf := make([]byte, 4096)
	for attempt := 0; attempt < 2; attempt++ {
		if _, err = pc.WriteTo(b, raddr); err != nil {
			ob.invalidate()
			return nil, ifc, err
		}
		_ = pc.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, _, rerr := pc.ReadFrom(buf)
		if rerr != nil {
			err = rerr
			continue
		}
		var r dns.Msg
		if err = r.Unpack(buf[:n]); err != nil || r.Id != m.Id {
			continue
		}
		return &r, ifc, nil
	}
	return nil, ifc, fmt.Errorf("no answer: %w", err)
}

func trimDot(s string) string {
	if len(s) > 0 && s[len(s)-1] == '.' {
		return s[:len(s)-1]
	}
	return s
}
