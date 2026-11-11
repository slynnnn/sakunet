//go:build !windows

package core

// tunAdminBlocker: no elevation concept gates TUN in non-Windows
// builds (the release target is Windows; Linux dev builds run as
// root in the test VM).
func tunAdminBlocker() string { return "" }
