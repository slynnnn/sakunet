//go:build !windows

// Package autostart stub for non-Windows builds (release target
// is Windows; the settings page hides the toggle when unsupported).
package autostart

import "errors"

func Supported() bool { return false }

func Enabled(string) (bool, error) { return false, nil }

func Set(bool, string) error { return errors.New("开机自启仅支持 Windows") }
