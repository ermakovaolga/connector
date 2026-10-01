package main

import (
	"encoding/json"
	"net/http"
	"os"
	"strings"
)

// Control API для кнопки в меню. Только 127.0.0.1.
// Заголовок X-VPNPoC обязателен: браузер не может выставить его чужой
// странице без CORS-preflight, который мы не разрешаем, — так сайт не
// сможет выключить агента через localhost.
const (
	ControlAddr   = "127.0.0.1:47391"
	ControlHeader = "X-VPNPoC"
)

func serveControl(a *Agent, statePath string) error {
	mux := http.NewServeMux()
	reply := func(w http.ResponseWriter) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(a.Status())
	}
	guard := func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get(ControlHeader) != "1" {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			h(w, r)
		}
	}
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("VPN Policy: это служебный адрес агента.\nУправление — значок (кружок) в строке меню справа вверху.\n"))
	})
	mux.HandleFunc("GET /status", guard(func(w http.ResponseWriter, r *http.Request) { reply(w) }))
	mux.HandleFunc("POST /on", guard(func(w http.ResponseWriter, r *http.Request) {
		_ = a.Start()
		saveState(statePath, true)
		reply(w)
	}))
	mux.HandleFunc("POST /off", guard(func(w http.ResponseWriter, r *http.Request) {
		a.Stop()
		saveState(statePath, false)
		reply(w)
	}))
	return http.ListenAndServe(ControlAddr, mux)
}

// Состояние вкл/выкл переживает перезагрузку. Нет файла = включено.
func loadState(path string) bool {
	b, err := os.ReadFile(path)
	return err != nil || strings.TrimSpace(string(b)) != "off"
}

func saveState(path string, on bool) {
	s := "off"
	if on {
		s = "on"
	}
	if err := os.WriteFile(path, []byte(s+"\n"), 0o644); err != nil {
		logf("WARN save state: %v", err)
	}
}
