// vpnpoc-tray: значок в строке меню (macOS) / в трее (Windows) с кнопкой
// вкл/выкл. Работает от пользователя и только говорит со службой vpnpoc
// через control API — пароль нужен один раз, при установке службы.
package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"runtime"
	"sort"
	"strings"
	"time"

	"fyne.io/systray"
)

const (
	controlURL    = "http://127.0.0.1:47391"
	controlHeader = "X-VPNPoC"
	logPath       = "/var/log/vpnpoc.log"
	testURL       = "http://d.dgx:18888"
)

type status struct {
	On        bool              `json:"on"`
	TUN       string            `json:"tun"`
	Error     string            `json:"error"`
	Outbounds map[string]string `json:"outbounds"`
}

var client = &http.Client{Timeout: 30 * time.Second}

func call(method, path string) (*status, error) {
	req, _ := http.NewRequest(method, controlURL+path, nil)
	req.Header.Set(controlHeader, "1")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	var s status
	return &s, json.NewDecoder(resp.Body).Decode(&s)
}

func main() { systray.Run(onReady, func() {}) }

func onReady() {
	systray.SetTooltip("VPN policy agent")
	mStatus := systray.AddMenuItem("…", "")
	mStatus.Disable()
	// Строки «itmo: ✓ utun6», по одной на outbound; создаём заранее, чтобы
	// они стояли под статусом (systray добавляет пункты только в конец).
	mOut := make([]*systray.MenuItem, 4)
	for i := range mOut {
		mOut[i] = systray.AddMenuItem("", "")
		mOut[i].Disable()
		mOut[i].Hide()
	}
	systray.AddSeparator()
	mToggle := systray.AddMenuItem("Включить", "Включить/выключить перехват")
	mTest := systray.AddMenuItem("Открыть "+strings.TrimPrefix(testURL, "http://"), "Проверка доступа к лаборатории")
	mLog := systray.AddMenuItem("Открыть лог", logPath)
	if runtime.GOOS != "darwin" {
		mLog.Hide()
	}
	systray.AddSeparator()
	mQuit := systray.AddMenuItem("Скрыть значок", "Агент продолжит работать в текущем состоянии")

	var cur *status
	render := func(s *status, err error) {
		cur = s
		switch {
		case err != nil:
			setIcon(colorWarn)
			mStatus.SetTitle("⚠ Служба не отвечает")
			mStatus.SetTooltip("Установите службу: install.sh (" + err.Error() + ")")
			mToggle.Disable()
		case s.On:
			setIcon(colorOn)
			mStatus.SetTitle("● Включено")
			mToggle.SetTitle("Выключить")
			mToggle.Enable()
		case s.Error != "":
			setIcon(colorWarn)
			mStatus.SetTitle("⚠ Не удалось включить, повторяю…")
			mStatus.SetTooltip(s.Error)
			mToggle.SetTitle("Выключить")
			mToggle.Enable()
		default:
			setIcon(colorOff)
			mStatus.SetTitle("○ Выключено")
			mToggle.SetTitle("Включить")
			mToggle.Enable()
		}
		var lines []string
		if s != nil {
			for name, v := range s.Outbounds {
				if strings.HasPrefix(v, "ERROR") {
					if name == "itmo" {
						v = "не подключён (FortiClient?)"
					} else {
						v = "нет сети"
					}
				} else {
					v = "✓ " + v
				}
				lines = append(lines, name+": "+v)
			}
			sort.Strings(lines)
		}
		for i, it := range mOut {
			if i < len(lines) {
				it.SetTitle("   " + lines[i])
				it.Show()
			} else {
				it.Hide()
			}
		}
	}

	refresh := func() { render(call("GET", "/status")) }
	refresh()

	go func() {
		t := time.NewTicker(3 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				refresh()
			case <-mToggle.ClickedCh:
				mToggle.Disable()
				path := "/on"
				if cur != nil && (cur.On || cur.Error != "") {
					path = "/off"
				}
				mStatus.SetTitle("… подождите")
				render(call("POST", path))
			case <-mTest.ClickedCh:
				open(testURL)
			case <-mLog.ClickedCh:
				open(logPath)
			case <-mQuit.ClickedCh:
				systray.Quit()
				return
			}
		}
	}()
}

func open(target string) {
	switch runtime.GOOS {
	case "darwin":
		_ = exec.Command("open", target).Start()
	case "windows":
		_ = exec.Command("rundll32", "url.dll,FileProtocolHandler", target).Start()
	}
}
