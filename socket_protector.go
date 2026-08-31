package libv2ray

import (
	"fmt"
	"syscall"

	"github.com/xtls/xray-core/transport/internet"
)

// SocketProtector lets the Android VpnService exempt Xray's own outbound sockets
// from the VPN before they connect. Without this, including the app UID in the VPN
// would route the core back into its own TUN interface.
type SocketProtector interface {
	Protect(socket int32) bool
}

// RegisterSocketProtector installs protection for every socket created by Xray's
// default system dialer. Register it once before starting the core.
func (x *CoreController) RegisterSocketProtector(protector SocketProtector) error {
	if protector == nil {
		return fmt.Errorf("socket protector is nil")
	}

	return internet.RegisterDialerController(func(network, address string, rawConn syscall.RawConn) error {
		var protectErr error
		controlErr := rawConn.Control(func(fd uintptr) {
			if !protector.Protect(int32(fd)) {
				protectErr = fmt.Errorf("VpnService rejected socket protection for fd %d", fd)
			}
		})
		if controlErr != nil {
			return fmt.Errorf("access socket for VPN protection: %w", controlErr)
		}
		return protectErr
	})
}
