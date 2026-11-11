//go:build windows

package core

import "sakunet/internal/elevate"

// tunAdminBlocker reports why enabling TUN must be refused right
// now, or "" when it may proceed. Creating a TUN inbound on
// Windows requires an elevated process; refusing up front (before
// persisting the preference) keeps a non-elevated instance from
// saving a preference that would make every later core start fail.
func tunAdminBlocker() string {
	if !elevate.IsAdmin() {
		return "TUN 需要管理员权限：请先在设置页点「以管理员重启」，再打开 TUN 开关"
	}
	return ""
}
