//go:build !windows

// Package elevate stub for non-Windows builds.
package elevate

import "errors"

func IsAdmin() bool { return false }

func Relaunch() error { return errors.New("self-elevation is only supported on Windows") }
