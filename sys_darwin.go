package main

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const defaultTUNName = "utun" // ядро само выдаст свободный utunN

type routeEntry struct {
	prefix  netip.Prefix
	gateway string
	iface   string
}

// routes разбирает `netstat -rn -f inet`. Сокращённые записи вида "10.32/16",
// "192.168.0" или "127" дополняются нулями; без "/" длина — по числу октетов.
func routes() ([]routeEntry, error) {
	out, err := sh("netstat", "-rn", "-f", "inet")
	if err != nil {
		return nil, err
	}
	var res []routeEntry
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 4 || f[0] == "Destination" {
			continue
		}
		dst, iface := f[0], f[3]
		if dst == "default" {
			res = append(res, routeEntry{netip.MustParsePrefix("0.0.0.0/0"), f[1], iface})
			continue
		}
		dst, _, _ = strings.Cut(dst, "%")
		addr, bitsStr, hasBits := strings.Cut(dst, "/")
		oct := strings.Split(addr, ".")
		if len(oct) > 4 {
			continue
		}
		bits := len(oct) * 8
		if hasBits {
			if bits, err = strconv.Atoi(bitsStr); err != nil {
				continue
			}
		}
		for len(oct) < 4 {
			oct = append(oct, "0")
		}
		ip, err := netip.ParseAddr(strings.Join(oct, "."))
		if err != nil || bits > 32 {
			continue
		}
		res = append(res, routeEntry{netip.PrefixFrom(ip, bits), f[1], iface})
	}
	return res, nil
}

// detectInterfaceFor ищет интерфейс с самым специфичным маршрутом до target,
// игнорируя default и "0/1 + 128/1" от full-tunnel VPN. Если FortiClient не
// подключён, специфичного маршрута на 10.32.x не будет — и мы честно упадём,
// а не отправим трафик в чужой VPN.
func detectInterfaceFor(target, exclude string) (string, error) {
	ip, err := netip.ParseAddr(target)
	if err != nil {
		return "", err
	}
	rs, err := routes()
	if err != nil {
		return "", err
	}
	best, bestBits := "", -1
	for _, r := range rs {
		if r.prefix.Bits() < 8 || r.iface == exclude || r.iface == "lo0" {
			continue
		}
		if r.prefix.Contains(ip) && r.prefix.Bits() > bestBits {
			best, bestBits = r.iface, r.prefix.Bits()
		}
	}
	if best == "" {
		return "", fmt.Errorf("no specific route to %s (VPN не подключён?)", target)
	}
	return best, nil
}

// detectPhysicalInterface — интерфейс default-маршрута, не являющийся туннелем.
func detectPhysicalInterface() (string, error) {
	iface, _, err := physicalDefault()
	return iface, err
}

func physicalDefault() (iface, gateway string, err error) {
	rs, err := routes()
	if err != nil {
		return "", "", err
	}
	for _, r := range rs {
		if r.prefix.Bits() == 0 && !isTunnel(r.iface) {
			return r.iface, r.gateway, nil
		}
	}
	return "", "", fmt.Errorf("no physical default route")
}

// networkFingerprint — физический интерфейс и шлюз по умолчанию.
func networkFingerprint() string {
	ifc, gw, err := physicalDefault()
	if err != nil {
		return ""
	}
	return ifc + " via " + gw
}

func isTunnel(name string) bool {
	for _, p := range []string{"utun", "ipsec", "ppp", "tun", "gif", "lo"} {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

func setupSystem(tun string, cfg *Config, obs map[string]*Outbound) (Cleanup, error) {
	var cl Cleanup
	fail := func(err error) (Cleanup, error) { cl.Run(); return nil, err }

	// Защита от второго экземпляра: fake-сеть уже маршрутизируется в чужой TUN.
	fake := netip.MustParsePrefix(cfg.TUN.FakeIPRange).Masked()
	if rs, err := routes(); err == nil {
		for _, r := range rs {
			if r.prefix == fake && r.iface != tun {
				return nil, fmt.Errorf("%s уже маршрутизируется в %s — другой экземпляр агента запущен?", fake, r.iface)
			}
		}
	}

	addr := cfg.TUN.Address
	if _, err := sh("ifconfig", tun, "inet", addr, addr, "up"); err != nil {
		return fail(err)
	}

	addRoute := func(cidr string) error {
		if _, err := sh("route", "-n", "add", "-net", cidr, "-interface", tun); err != nil {
			return err
		}
		logf("route %s -> %s", cidr, tun)
		cl.Add(func() { _, _ = sh("route", "-n", "delete", "-net", cidr, "-interface", tun) })
		return nil
	}
	if err := addRoute(cfg.TUN.FakeIPRange); err != nil {
		return fail(err)
	}
	// Сокет с IP_BOUND_IF=X в macOS находит маршрут, только если самый
	// специфичный маршрут ведёт в X или есть scoped-маршрут (-ifscope X).
	// Full-tunnel VPN (0/1 + 128/1) оставляет en0 без scoped default, и
	// direct-сокеты получают "network is unreachable". Добавляем его.
	addScoped := func(args ...string) {
		if _, err := sh("route", append([]string{"-n", "add"}, args...)...); err != nil {
			logf("WARN %v", err)
			return
		}
		logf("route %s", strings.Join(args, " "))
		cl.Add(func() { _, _ = sh("route", append([]string{"-n", "delete"}, args...)...) })
	}
	ifc, gw, err := physicalDefault()
	if err != nil {
		return fail(err)
	}
	if out, _ := sh("route", "-n", "get", "-ifscope", ifc, "default"); !strings.Contains(out, "interface: "+ifc) {
		addScoped("-ifscope", ifc, "default", gw)
	}
	for _, b := range cfg.Bypass {
		if _, err := sh("route", "-n", "add", "-net", b, gw); err != nil {
			logf("WARN bypass %v", err)
			continue
		}
		logf("route %s -> %s via %s (bypass)", b, gw, ifc)
		cl.Add(func() { _, _ = sh("route", "-n", "delete", "-net", b, gw) })
	}

	if cfg.CaptureIPRules {
		for _, r := range cfg.Rules {
			for _, c := range r.IPCIDR {
				if err := addRoute(c); err != nil {
					return fail(err)
				}
				// Наш /32 в TUN перебьёт маршрут VPN и для привязанного сокета,
				// поэтому дублируем его scoped-маршрутом на интерфейс outbound.
				if ifc, err := obs[r.Outbound].Interface(); err == nil {
					addScoped("-net", c, "-interface", ifc.Name, "-ifscope", ifc.Name)
				} else {
					logf("WARN %v: scoped route for %s not added", err, c)
				}
			}
		}
	}

	// Split DNS: только домены из правил идут в наш DNS, остальное как было.
	if err := os.MkdirAll("/etc/resolver", 0o755); err != nil {
		return fail(err)
	}
	for _, r := range cfg.Rules {
		for _, suffix := range r.DomainSuffix {
			path := filepath.Join("/etc/resolver", suffix)
			if b, err := os.ReadFile(path); err == nil && !strings.Contains(string(b), managedMarker) {
				return fail(fmt.Errorf("%s уже существует и не наш — не трогаю", path))
			}
			body := fmt.Sprintf("# %s\nnameserver %s\n", managedMarker, cfg.TUN.DNSAddress)
			if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
				return fail(err)
			}
			logf("dns  *.%s -> %s (%s)", suffix, cfg.TUN.DNSAddress, path)
			cl.Add(func() { _ = os.Remove(path) })
		}
	}
	flush := func() {
		_, _ = sh("dscacheutil", "-flushcache")
		_, _ = sh("killall", "-HUP", "mDNSResponder")
	}
	flush()
	cl.Add(flush)
	return cl, nil
}

// cleanupStale убирает следы агента, убитого без очистки (kill -9, выключение
// питания): иначе /etc/resolver/<suffix> шлёт DNS на мёртвый адрес.
func cleanupStale() {
	files, _ := filepath.Glob("/etc/resolver/*")
	for _, f := range files {
		if b, err := os.ReadFile(f); err == nil && strings.Contains(string(b), managedMarker) {
			if os.Remove(f) == nil {
				logf("stale %s removed", f)
			}
		}
	}
}

// addScopedDefault: default-маршрут только для сокетов, привязанных к iface
// (IP_BOUND_IF). Обычный трафик системы его не видит.
func addScopedDefault(iface string) (func(), error) {
	args := []string{"-ifscope", iface, "default", "-interface", iface}
	if out, err := sh("route", append([]string{"-n", "add"}, args...)...); err != nil && !strings.Contains(out, "File exists") {
		return nil, err
	}
	logf("route default -ifscope %s (scoped default)", iface)
	return func() { _, _ = sh("route", append([]string{"-n", "delete"}, args...)...) }, nil
}
