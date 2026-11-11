//go:build windows

// Package elevate provides Windows admin detection and UAC
// self-relaunch (ShellExecute "runas"), used by the TUN toggle:
// TUN inbound needs Administrator on Windows.
package elevate

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

var (
	advapi32            = syscall.NewLazyDLL("advapi32.dll")
	fnOpenProcessToken  = advapi32.NewProc("OpenProcessToken")
	fnGetTokenInfo      = advapi32.NewProc("GetTokenInformation")
	shell32             = syscall.NewLazyDLL("shell32.dll")
	fnShellExecuteW     = shell32.NewProc("ShellExecuteW")
	kernel32            = syscall.NewLazyDLL("kernel32.dll")
	fnGetCurrentProcess = kernel32.NewProc("GetCurrentProcess")
	fnCloseHandle       = kernel32.NewProc("CloseHandle")
)

const (
	tokenQuery        = 0x0008
	tokenElevation    = 20
	seErrAccessDenied = 5
	swShownormal      = 1
)

// IsAdmin reports whether the current process runs elevated.
func IsAdmin() bool {
	proc, _, _ := fnGetCurrentProcess.Call()
	var token uintptr
	r, _, _ := fnOpenProcessToken.Call(proc, tokenQuery, uintptr(unsafe.Pointer(&token)))
	if r == 0 {
		return false
	}
	defer fnCloseHandle.Call(token)
	var elevation uint32
	var retLen uint32
	r, _, _ = fnGetTokenInfo.Call(token, tokenElevation,
		uintptr(unsafe.Pointer(&elevation)), 4,
		uintptr(unsafe.Pointer(&retLen)))
	return r != 0 && elevation != 0
}

// Relaunch restarts SakuNet with the "runas" verb (UAC prompt),
// forwarding the current command-line arguments.
func Relaunch() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	verb, _ := syscall.UTF16PtrFromString("runas")
	file, _ := syscall.UTF16PtrFromString(exe)
	params, _ := syscall.UTF16PtrFromString(joinArgs(os.Args[1:]))
	dir, _ := syscall.UTF16PtrFromString(cwdOf(exe))
	r, _, _ := fnShellExecuteW.Call(
		0,
		uintptr(unsafe.Pointer(verb)),
		uintptr(unsafe.Pointer(file)),
		uintptr(unsafe.Pointer(params)),
		uintptr(unsafe.Pointer(dir)),
		swShownormal,
	)
	if r <= 32 {
		return fmt.Errorf("ShellExecute runas failed (code %d)", r)
	}
	return nil
}

func joinArgs(args []string) string {
	out := ""
	for i, a := range args {
		if i > 0 {
			out += " "
		}
		out += `"` + a + `"`
	}
	return out
}

func cwdOf(exe string) string {
	for i := len(exe) - 1; i >= 0; i-- {
		if exe[i] == '\\' || exe[i] == '/' {
			return exe[:i]
		}
	}
	return "."
}
