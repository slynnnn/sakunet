// Package tray provides the Windows system-tray front end
// (fyne.io/systray). On other platforms Run reports unsupported
// and the caller keeps the plain HTTP-server behaviour.
package tray

import _ "embed"

//go:embed icon.ico
var iconICO []byte

// Callbacks wires the tray menu to the app.
type Callbacks struct {
	Status    func() (running bool, mode string)
	Start     func() error
	Stop      func() error
	SetMode   func(mode string) error
	OpenPanel func()
	Quit      func()
}

// Supported reports whether a tray is available on this platform.
func Supported() bool { return supported }
