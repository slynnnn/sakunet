//go:build windows

package tray

import (
	"os/exec"
	"time"

	"fyne.io/systray"
)

const supported = true

// Run blocks in the systray event loop (call from the main
// goroutine on Windows).
func Run(cb Callbacks) error {
	systray.Run(func() { onReady(cb) }, func() {})
	return nil
}

func onReady(cb Callbacks) {
	systray.SetIcon(iconICO)
	systray.SetTitle("SakuNet")
	systray.SetTooltip("SakuNet")

	mState := systray.AddMenuItem("未连接", "当前状态")
	mState.Disable()
	mOpen := systray.AddMenuItem("打开面板", "在浏览器打开控制面板")
	systray.AddSeparator()
	mPower := systray.AddMenuItem("启动内核", "启动/停止 sing-box 内核")
	systray.AddSeparator()
	mMode := systray.AddMenuItem("模式", "路由模式")
	mRule := mMode.AddSubMenuItemCheckbox("规则分流", "按规则分流", true)
	mGlobal := mMode.AddSubMenuItemCheckbox("全部代理", "全部走代理", false)
	mDirect := mMode.AddSubMenuItemCheckbox("全部直连", "全部直连", false)
	systray.AddSeparator()
	mQuit := systray.AddMenuItem("退出", "停止内核并退出 SakuNet")

	refresh := func() {
		running, mode := cb.Status()
		if running {
			mState.SetTitle("已连接")
			mPower.SetTitle("停止内核")
		} else {
			mState.SetTitle("未连接")
			mPower.SetTitle("启动内核")
		}
		mRule.Uncheck()
		mGlobal.Uncheck()
		mDirect.Uncheck()
		switch mode {
		case "global":
			mGlobal.Check()
		case "direct":
			mDirect.Check()
		default:
			mRule.Check()
		}
	}
	refresh()
	go func() {
		t := time.NewTicker(2 * time.Second)
		defer t.Stop()
		for range t.C {
			refresh()
		}
	}()

	go func() {
		for {
			select {
			case <-mOpen.ClickedCh:
				cb.OpenPanel()
			case <-mPower.ClickedCh:
				running, _ := cb.Status()
				if running {
					_ = cb.Stop()
				} else {
					_ = cb.Start()
				}
				refresh()
			case <-mRule.ClickedCh:
				_ = cb.SetMode("rule")
				refresh()
			case <-mGlobal.ClickedCh:
				_ = cb.SetMode("global")
				refresh()
			case <-mDirect.ClickedCh:
				_ = cb.SetMode("direct")
				refresh()
			case <-mQuit.ClickedCh:
				cb.Quit()
				systray.Quit()
				return
			}
		}
	}()
}

// OpenBrowser opens the dashboard in the default browser.
func OpenBrowser(url string) {
	_ = exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
}
