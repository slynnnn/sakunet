//go:build !windows

// Package sysproxy stub for non-Windows builds (CI / development).
package sysproxy

import "errors"

func Set(addr string) error { return errors.New("system proxy is only supported on Windows") }
func Clear() error          { return errors.New("system proxy is only supported on Windows") }

// Current reports (enabled, server) of the OS system proxy.
func Current() (bool, string, error) {
	return false, "", errors.New("system proxy is only supported on Windows")
}
