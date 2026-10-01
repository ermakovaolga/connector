// vpn-policy-poc: локальный policy-агент.
//
//	приложение → TUN → gVisor netstack → policy → сокет, привязанный к
//	интерфейсу нужного VPN (FortiClient utunN) или физическому (direct).
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/miekg/dns"
)

func usage() {
	fmt.Fprintf(os.Stderr, `usage:
  vpnpoc probe [-c config.yaml] [host:port ...]   проверка без root: интерфейсы, DNS, bound-dial
  vpnpoc run   [-c config.yaml]                   запустить агент в терминале (sudo)
  vpnpoc daemon [-c config.yaml] [-state file]    режим службы с кнопкой в меню (root)
`)
	os.Exit(2)
}

func main() {
	log.SetFlags(log.Ltime | log.Lmicroseconds)
	if len(os.Args) < 2 {
		usage()
	}
	cmd := os.Args[1]
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	cfgPath := fs.String("c", "config.yaml", "config file")
	statePath := fs.String("state", "state", "daemon: файл состояния вкл/выкл")
	_ = fs.Parse(os.Args[2:])

	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	switch cmd {
	case "run":
		err = run(cfg)
	case "daemon":
		err = daemon(cfg, *statePath)
	case "probe":
		err = probe(cfg, fs.Args())
	default:
		usage()
	}
	if err != nil {
		log.Fatal(err)
	}
}

func newOutbounds(cfg *Config, tunName string) map[string]*Outbound {
	obs := map[string]*Outbound{}
	for name, oc := range cfg.Outbounds {
		obs[name] = NewOutbound(name, oc, tunName)
	}
	return obs
}

// run — ручной режим из терминала: включено, пока не нажат Ctrl+C.
func run(cfg *Config) error {
	cleanupStale()
	a := NewAgent(cfg)
	if err := a.Start(); err != nil {
		return err
	}
	defer a.Stop()
	done := make(chan struct{})
	defer close(done)
	go a.Watch(done)
	logf("ready. Ctrl+C для остановки")
	waitSignal()
	return nil
}

// daemon — режим службы: control API для кнопки в меню, состояние вкл/выкл
// помнится между перезагрузками.
func daemon(cfg *Config, statePath string) error {
	cleanupStale()
	a := NewAgent(cfg)
	if loadState(statePath) {
		_ = a.Start() // при ошибке Watch повторит
	} else {
		logf("OFF (выключено пользователем)")
	}
	done := make(chan struct{})
	go a.Watch(done)
	errc := make(chan error, 1)
	go func() { errc <- serveControl(a, statePath) }()
	logf("control API %s (служебный, для значка в меню; не для браузера)", ControlAddr)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	var err error
	select {
	case <-sig:
	case err = <-errc:
	}
	close(done)
	// Состояние не сохраняем: остановка службы != «пользователь выключил».
	a.Stop()
	return err
}

func waitSignal() {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP) // SIGHUP: закрыли окно терминала
	<-sig
}

// probe проверяет ключевой механизм без root и без TUN: можно ли, привязав
// сокет к интерфейсу outbound, достучаться до цели — и что без привязки к
// нужному интерфейсу (негативный контроль) цель недоступна.
func probe(cfg *Config, targets []string) error {
	obs := newOutbounds(cfg, "")
	policy := &Policy{cfg: cfg}
	pool := NewFakeIPPool(netip.MustParsePrefix(cfg.TUN.FakeIPRange))
	dnsSrv := &DNSServer{policy: policy, pool: pool, outbounds: obs}

	fmt.Println("== outbounds")
	for name, ob := range obs {
		ifc, err := ob.Interface()
		if err != nil {
			fmt.Printf("  %-6s ERROR %v\n", name, err)
			continue
		}
		fmt.Printf("  %-6s -> %s (index %d)\n", name, ifc.Name, ifc.Index)
	}

	if len(targets) == 0 {
		targets = []string{"d.dgx:18888", "10.32.2.11:18888", "10.32.0.3:443", "10.32.15.89:443", "10.32.1.3:53", "example.com:443"}
	}
	fmt.Println("== targets (policy / bound dial / negative control)")
	for _, t := range targets {
		host, port, err := net.SplitHostPort(t)
		if err != nil {
			fmt.Printf("  %s: %v\n", t, err)
			continue
		}
		ipStr, obName := host, ""
		if _, err := netip.ParseAddr(host); err != nil {
			rule := policy.MatchDomain(host)
			if rule == nil || len(rule.DNS) == 0 {
				ips, err := net.LookupHost(host)
				if err != nil || len(ips) == 0 {
					fmt.Printf("  %-22s DNS FAIL %v\n", t, err)
					continue
				}
				ipStr = ips[0]
			} else {
				ipStr, err = resolveVia(dnsSrv, obs[rule.Outbound], host, rule.DNS[0])
				if err != nil {
					fmt.Printf("  %-22s DNS via %s[%s] FAIL %v\n", t, rule.Outbound, rule.DNS, err)
					continue
				}
				fmt.Printf("  %-22s DNS %s via %s -> %s\n", t, rule.DNS, rule.Outbound, ipStr)
				obName = rule.Outbound
			}
		}
		if obName == "" {
			obName = policy.MatchIP(netip.MustParseAddr(ipStr))
		}
		addr := net.JoinHostPort(ipStr, port)
		fmt.Printf("  %-22s policy=%-6s %s\n", t, obName, dialResult(obs[obName], addr))
		for other, ob := range obs {
			if other != obName {
				fmt.Printf("  %-22s   control via %-6s %s\n", "", other, dialResult(ob, addr))
			}
		}
	}
	return nil
}

func resolveVia(s *DNSServer, ob *Outbound, host, server string) (string, error) {
	q := new(dns.Msg)
	q.SetQuestion(dns.Fqdn(host), dns.TypeA)
	r, _, err := s.exchange(ob, q, server)
	if err != nil {
		return "", err
	}
	for _, rr := range r.Answer {
		if a, ok := rr.(*dns.A); ok {
			return a.A.String(), nil
		}
	}
	return "", fmt.Errorf("no A record (rcode %s)", dns.RcodeToString[r.Rcode])
}

func dialResult(ob *Outbound, addr string) string {
	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	c, ifc, err := ob.DialContext(ctx, "tcp4", addr)
	d := time.Since(start).Round(time.Millisecond)
	if err != nil {
		msg := err.Error()
		switch {
		case strings.Contains(msg, "refused"):
			return fmt.Sprintf("REFUSED (%s) — хост достижим, порт закрыт", d)
		case strings.Contains(msg, "timeout"), strings.Contains(msg, "deadline"):
			return fmt.Sprintf("TIMEOUT (%s)", d)
		}
		if strings.Contains(msg, "unreachable") {
			return fmt.Sprintf("UNREACHABLE — нет маршрута через %s (для direct при full-tunnel VPN: нужен scoped default, его ставит `run`)", ob.Name)
		}
		return fmt.Sprintf("FAIL %v", err)
	}
	c.Close()
	return fmt.Sprintf("CONNECTED via %s (%s)", ifc.Name, d)
}
