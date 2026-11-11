//go:build windows

// Package autostart manages the Windows "start at login" entry
// (HKCU Run key). Per-user, no elevation needed, removed cleanly
// when disabled.
package autostart

import (
	"fmt"
	"strings"

	"golang.org/x/sys/windows/registry"
)

const (
	runKeyPath = `Software\Microsoft\Windows\CurrentVersion\Run`
	valueName  = "SakuNet"
)

// Supported reports whether this platform has autostart support.
func Supported() bool { return true }

// Enabled reports whether the Run entry exists and points at
// exePath (any SakuNet entry counts when exePath is empty).
func Enabled(exePath string) (bool, error) {
	k, err := registry.OpenKey(registry.CURRENT_USER, runKeyPath, registry.QUERY_VALUE)
	if err != nil {
		return false, err
	}
	defer k.Close()
	v, _, err := k.GetStringValue(valueName)
	if err != nil {
		return false, nil // value absent
	}
	if exePath == "" {
		return true, nil
	}
	return strings.Contains(strings.ToLower(v), strings.ToLower(exePath)), nil
}

// Set installs or removes the Run entry for exePath.
func Set(on bool, exePath string) error {
	k, err := registry.OpenKey(registry.CURRENT_USER, runKeyPath, registry.SET_VALUE|registry.QUERY_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	if !on {
		err := k.DeleteValue(valueName)
		if err != nil && err != registry.ErrNotExist {
			return err
		}
		return nil
	}
	if exePath == "" {
		return fmt.Errorf("autostart: empty executable path")
	}
	return k.SetStringValue(valueName, `"`+exePath+`"`)
}
