//go:build !windows

package tray

import "errors"

const supported = false

// Run is unsupported off Windows.
func Run(cb Callbacks) error { return errors.New("tray is only supported on Windows") }

// OpenBrowser is a no-op off Windows (the tray never runs there).
func OpenBrowser(url string) {}
