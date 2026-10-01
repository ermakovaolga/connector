package main

import (
	"fmt"
	"log"
	"os/exec"
	"strings"
)

const managedMarker = "managed by vpn-policy-poc"

func logf(format string, args ...any) { log.Printf(format, args...) }

// sh выполняет системную команду; ошибки возвращает вместе с выводом.
func sh(name string, args ...string) (string, error) {
	out, err := exec.Command(name, args...).CombinedOutput()
	s := strings.TrimSpace(string(out))
	if err != nil {
		return s, fmt.Errorf("%s %s: %v: %s", name, strings.Join(args, " "), err, s)
	}
	return s, nil
}

// Cleanup — стек действий отката, выполняется в обратном порядке.
type Cleanup []func()

func (c *Cleanup) Add(f func()) { *c = append(*c, f) }

func (c Cleanup) Run() {
	for i := len(c) - 1; i >= 0; i-- {
		c[i]()
	}
}
