package main

import (
	"fmt"
	"net/netip"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

type Config struct {
	TUN struct {
		Name        string `yaml:"name"`          // "utun" на macOS = автоназначение номера
		Address     string `yaml:"address"`       // адрес самого TUN
		DNSAddress  string `yaml:"dns_address"`   // адрес встроенного DNS (внутри TUN-сети)
		FakeIPRange string `yaml:"fake_ip_range"` // сеть, целиком маршрутизируемая в TUN
		MTU         uint32 `yaml:"mtu"`
	} `yaml:"tun"`

	Outbounds map[string]OutboundConfig `yaml:"outbounds"`
	Rules     []RuleConfig              `yaml:"rules"`
	Default   string                    `yaml:"default"`

	// Добавлять маршруты для ip_cidr-правил в TUN. Экспериментально:
	// эти маршруты пересекаются с маршрутами FortiClient.
	CaptureIPRules bool `yaml:"capture_ip_rules"`

	// Сети, которые всегда идут через физический интерфейс (host-маршрутом
	// мимо любых туннелей). Сюда кладутся шлюзы VPN: иначе full-tunnel VPN
	// (0/1 + 128/1) заворачивает в себя внешнее соединение FortiClient.
	Bypass []string `yaml:"bypass"`
}

type OutboundConfig struct {
	// "auto" или имя интерфейса (utun6 / "FortiClient ..." на Windows).
	Interface string `yaml:"interface"`
	// Для auto: адрес, по маршруту к которому ищется интерфейс
	// (ITMO: 10.32.1.3). Пусто = физический интерфейс default-маршрута.
	DetectBy string `yaml:"detect_by"`
	// Добавить scoped default на интерфейс (-ifscope): тогда через этот VPN
	// можно отправить и адреса, на которые VPN сам маршрут не выдал
	// (например, публичный сайт, пускающий только с адресов ITMO).
	// Действует только на сокеты агента, остальной трафик не меняется.
	ScopedDefault bool `yaml:"scoped_default"`
}

// StringList принимает и `dns: 10.32.1.3`, и `dns: [10.32.1.3, 8.8.8.8]`.
type StringList []string

func (l *StringList) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind == yaml.ScalarNode {
		*l = StringList{n.Value}
		return nil
	}
	var v []string
	if err := n.Decode(&v); err != nil {
		return err
	}
	*l = v
	return nil
}

type RuleConfig struct {
	DomainSuffix []string   `yaml:"domain_suffix"`
	IPCIDR       []string   `yaml:"ip_cidr"`
	Outbound     string     `yaml:"outbound"`
	DNS          StringList `yaml:"dns"` // upstream DNS для domain_suffix (по порядку), ходят через тот же outbound
}

func loadConfig(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	if err := yaml.Unmarshal(b, &c); err != nil {
		return nil, err
	}
	if c.TUN.Name == "" {
		c.TUN.Name = defaultTUNName
	}
	if c.TUN.MTU == 0 {
		c.TUN.MTU = 1500
	}
	if _, ok := c.Outbounds[c.Default]; !ok {
		return nil, fmt.Errorf("default outbound %q not defined", c.Default)
	}
	for _, b := range c.Bypass {
		if _, err := netip.ParsePrefix(b); err != nil {
			return nil, fmt.Errorf("bypass: %w", err)
		}
	}
	for i, r := range c.Rules {
		if _, ok := c.Outbounds[r.Outbound]; !ok {
			return nil, fmt.Errorf("rule %d: outbound %q not defined", i, r.Outbound)
		}
		for _, p := range r.IPCIDR {
			if _, err := netip.ParsePrefix(p); err != nil {
				return nil, fmt.Errorf("rule %d: %w", i, err)
			}
		}
		for j, s := range r.DomainSuffix {
			c.Rules[i].DomainSuffix[j] = strings.Trim(strings.ToLower(s), ".")
		}
	}
	return &c, nil
}
