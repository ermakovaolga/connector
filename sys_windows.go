package main

// Windows-вариант: тот же агент, другие системные команды.
// Требует wintun.dll (https://www.wintun.net) рядом с exe и запуск от администратора.
// Статус: компилируется, на реальной машине ещё не проверялся.

import (
	"fmt"
	"net/netip"
	"strings"
)

const defaultTUNName = "vpnpoc"

func ps(script string) (string, error) {
	return sh("powershell", "-NoProfile", "-NonInteractive", "-Command", script)
}

func detectInterfaceFor(target, exclude string) (string, error) {
	out, err := ps(fmt.Sprintf(
		`Find-NetRoute -RemoteIPAddress %s | Where-Object { $_.DestinationPrefix -and $_.DestinationPrefix -notin @('0.0.0.0/0','0.0.0.0/1','128.0.0.0/1') } | Select-Object -First 1 -ExpandProperty InterfaceAlias`,
		target))
	if err != nil {
		return "", err
	}
	if out == "" || out == exclude {
		return "", fmt.Errorf("no specific route to %s (VPN не подключён?)", target)
	}
	return out, nil
}

func detectPhysicalInterface() (string, error) {
	out, err := ps(`Get-NetRoute -DestinationPrefix 0.0.0.0/0 | Where-Object { Get-NetAdapter -InterfaceIndex $_.ifIndex -Physical -ErrorAction SilentlyContinue } | Sort-Object RouteMetric | Select-Object -First 1 -ExpandProperty InterfaceAlias`)
	if err != nil {
		return "", err
	}
	if out == "" {
		return "", fmt.Errorf("no physical default route")
	}
	return out, nil
}

func setupSystem(tun string, cfg *Config, _ map[string]*Outbound) (Cleanup, error) {
	var cl Cleanup
	fail := func(err error) (Cleanup, error) { cl.Run(); return nil, err }

	// Адрес с маской fake-сети: Windows сам создаст on-link маршрут на всю сеть.
	fake := netip.MustParsePrefix(cfg.TUN.FakeIPRange)
	mask := prefixMask(fake.Bits())
	if _, err := sh("netsh", "interface", "ipv4", "set", "address", "name="+tun, "static", cfg.TUN.Address, mask); err != nil {
		return fail(err)
	}
	logf("route %s -> %s", cfg.TUN.FakeIPRange, tun)

	if cfg.CaptureIPRules {
		for _, r := range cfg.Rules {
			for _, c := range r.IPCIDR {
				if _, err := sh("netsh", "interface", "ipv4", "add", "route", "prefix="+c, "interface="+tun, "store=active"); err != nil {
					return fail(err)
				}
				c := c
				cl.Add(func() {
					_, _ = sh("netsh", "interface", "ipv4", "delete", "route", "prefix="+c, "interface="+tun)
				})
			}
		}
	}

	if len(cfg.Bypass) > 0 {
		logf("WARN bypass на Windows пока не реализован")
	}

	// Split DNS через NRPT.
	for _, r := range cfg.Rules {
		for _, suffix := range r.DomainSuffix {
			if _, err := ps(fmt.Sprintf(`Add-DnsClientNrptRule -Namespace ".%s" -NameServers %s -Comment "%s"`,
				suffix, cfg.TUN.DNSAddress, managedMarker)); err != nil {
				return fail(err)
			}
			logf("dns  *.%s -> %s (NRPT)", suffix, cfg.TUN.DNSAddress)
		}
	}
	cl.Add(func() {
		_, _ = ps(fmt.Sprintf(`Get-DnsClientNrptRule | Where-Object Comment -eq "%s" | Remove-DnsClientNrptRule -Force`, managedMarker))
		_, _ = ps(`Clear-DnsClientCache`)
	})
	_, _ = ps(`Clear-DnsClientCache`)
	return cl, nil
}

func prefixMask(bits int) string {
	m := ^uint32(0) << (32 - bits)
	return strings.Join([]string{
		fmt.Sprint(m >> 24), fmt.Sprint(m >> 16 & 0xff), fmt.Sprint(m >> 8 & 0xff), fmt.Sprint(m & 0xff),
	}, ".")
}

// networkFingerprint: на Windows отслеживание смены сети пока не сделано.
func networkFingerprint() string { return "" }

// cleanupStale убирает NRPT-правила, оставшиеся от агента, убитого без очистки.
func cleanupStale() {
	_, _ = ps(fmt.Sprintf(`Get-DnsClientNrptRule | Where-Object Comment -eq "%s" | Remove-DnsClientNrptRule -Force`, managedMarker))
}

// addScopedDefault: на Windows IP_UNICAST_IF обходится без отдельного маршрута.
func addScopedDefault(string) (func(), error) { return func() {}, nil }
