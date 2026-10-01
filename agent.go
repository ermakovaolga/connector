package main

import (
	"fmt"
	"net/netip"
	"sync"
	"time"

	"github.com/xjasonlyu/tun2socks/v2/core"
	"github.com/xjasonlyu/tun2socks/v2/core/device"
	"github.com/xjasonlyu/tun2socks/v2/core/device/tun"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// Agent включает/выключает перехват. Служба держит его всё время,
// кнопка в меню дёргает Start/Stop через control API.
type Agent struct {
	cfg     *Config
	idleObs map[string]*Outbound // для статуса, пока выключено (кеш интерфейсов, без спама в лог)

	mu      sync.Mutex
	want    bool // пользователь хочет «включено»; Watch повторяет старт
	sess    *session
	lastErr string
	since   time.Time
}

type session struct {
	dev      device.Device
	st       *stack.Stack
	cleanup  Cleanup
	obs      map[string]*Outbound
	netState string
}

type Status struct {
	On        bool              `json:"on"`
	TUN       string            `json:"tun,omitempty"`
	Since     time.Time         `json:"since,omitzero"`
	Error     string            `json:"error,omitempty"`
	Outbounds map[string]string `json:"outbounds"` // имя -> интерфейс или "ERROR: ..."
}

func NewAgent(cfg *Config) *Agent { return &Agent{cfg: cfg, idleObs: newOutbounds(cfg, "")} }

func (a *Agent) Start() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.want = true
	if a.sess != nil {
		return nil
	}
	s, err := a.startSession()
	if err != nil {
		a.lastErr = err.Error()
		logf("start FAIL: %v", err)
		return err
	}
	a.sess, a.lastErr, a.since = s, "", time.Now()
	logf("ON (tun %s)", s.dev.Name())
	return nil
}

func (a *Agent) Stop() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.want = false
	a.lastErr = ""
	if a.sess == nil {
		return
	}
	a.sess.close()
	a.sess, a.since = nil, time.Now()
	logf("OFF")
}

func (a *Agent) Status() Status {
	a.mu.Lock()
	defer a.mu.Unlock()
	st := Status{On: a.sess != nil, Since: a.since, Error: a.lastErr, Outbounds: map[string]string{}}
	obs := a.idleObs
	if a.sess != nil {
		st.TUN = a.sess.dev.Name()
		obs = a.sess.obs
	}
	for name, ob := range obs {
		if ifc, err := ob.Interface(); err != nil {
			st.Outbounds[name] = "ERROR: " + err.Error()
		} else {
			st.Outbounds[name] = ifc.Name
		}
	}
	return st
}

// Watch: при смене сети (другой Wi-Fi) bypass/scoped-маршруты указывают на
// старый шлюз — пересобираем сессию. И повторяем неудавшийся старт
// (например, при загрузке сеть ещё не поднялась).
func (a *Agent) Watch(done <-chan struct{}) {
	tick := time.NewTicker(10 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-done:
			return
		case <-tick.C:
		}
		a.mu.Lock()
		changed := a.sess != nil && networkFingerprint() != a.sess.netState
		retry := a.want && a.sess == nil
		a.mu.Unlock()
		switch {
		case changed:
			logf("сеть сменилась, пересобираю маршруты")
			a.Stop()
			_ = a.Start()
		case retry:
			_ = a.Start()
		}
	}
}

func (a *Agent) startSession() (*session, error) {
	cfg := a.cfg
	dev, err := tun.Open(cfg.TUN.Name, cfg.TUN.MTU)
	if err != nil {
		return nil, fmt.Errorf("open tun (нужны права администратора): %w", err)
	}
	s := &session{dev: dev, netState: networkFingerprint()}
	tunName := dev.Name()
	logf("tun  %s up, mtu %d", tunName, cfg.TUN.MTU)

	policy := &Policy{cfg: cfg}
	pool := NewFakeIPPool(netip.MustParsePrefix(cfg.TUN.FakeIPRange))
	s.obs = newOutbounds(cfg, tunName)
	for _, ob := range s.obs {
		ob.manage = true
		if _, err := ob.Interface(); err != nil {
			logf("WARN %v (повторю при первом соединении)", err)
		}
	}
	h := &Handler{
		policy: policy, pool: pool, outbounds: s.obs,
		dns:     &DNSServer{policy: policy, pool: pool, outbounds: s.obs},
		dnsAddr: netip.MustParseAddr(cfg.TUN.DNSAddress),
	}
	if s.st, err = core.CreateStack(&core.Config{LinkEndpoint: dev, TransportHandler: h}); err != nil {
		dev.Close()
		return nil, err
	}
	if s.cleanup, err = setupSystem(tunName, cfg, s.obs); err != nil {
		for _, ob := range s.obs {
			ob.Close()
		}
		s.st.Close()
		dev.Close()
		return nil, err
	}
	return s, nil
}

func (s *session) close() {
	logf("cleanup")
	s.cleanup.Run()
	for _, ob := range s.obs {
		ob.Close()
	}
	s.st.Close()
	s.dev.Close()
}
