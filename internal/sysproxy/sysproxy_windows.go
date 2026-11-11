//go:build windows

// Package sysproxy toggles the Windows per-user system proxy
// (HKCU Internet Settings) using the registry via reg.exe and
// notifies WinINET of the change. Stdlib only, no cgo.
package sysproxy

import (
	"fmt"
	"os/exec"
	"strings"
	"syscall"
	"unsafe"
)

const regKey = `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings`

func regSet(name, typ, val string) error {
	out, err := exec.Command("reg", "add", regKey, "/v", name, "/t", typ, "/d", val, "/f").CombinedOutput()
	if err != nil {
		return fmt.Errorf("reg add %s: %v: %s", name, err, out)
	}
	return nil
}

var (
	wininet           = syscall.NewLazyDLL("wininet.dll")
	internetSetOption = wininet.NewProc("InternetSetOptionW")
	settingsChanged   = uintptr(39) // INTERNET_OPTION_SETTINGS_CHANGED
	refresh           = uintptr(37) // INTERNET_OPTION_REFRESH
)

func notify() {
	internetSetOption.Call(0, settingsChanged, 0, 0)
	internetSetOption.Call(0, refresh, 0, 0)
}

// Set enables the system proxy pointing at addr ("127.0.0.1:2080").
func Set(addr string) error {
	if err := regSet("ProxyServer", "REG_SZ", addr); err != nil {
		return err
	}
	if err := regSet("ProxyOverride", "REG_SZ", "localhost;127.*;192.168.*;10.*;172.16.*;<local>"); err != nil {
		return err
	}
	if err := regSet("ProxyEnable", "REG_DWORD", "1"); err != nil {
		return err
	}
	notify()
	return nil
}

// Clear disables the system proxy.
func Clear() error {
	if err := regSet("ProxyEnable", "REG_DWORD", "0"); err != nil {
		return err
	}
	notify()
	return nil
}

func regQuery(name string) (string, error) {
	out, err := exec.Command("reg", "query", regKey, "/v", name).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("reg query %s: %v", name, err)
	}
	// Output shape: "    ProxyEnable    REG_DWORD    0x1"
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(line)
		if len(f) >= 3 && f[0] == name {
			return f[len(f)-1], nil
		}
	}
	return "", fmt.Errorf("reg query %s: value not found", name)
}

// Current reports (enabled, server) of the per-user system proxy.
func Current() (bool, string, error) {
	en, err := regQuery("ProxyEnable")
	if err != nil {
		return false, "", err
	}
	srv, _ := regQuery("ProxyServer")
	return en == "0x1", srv, nil
}

var _ = unsafe.Sizeof(0)
