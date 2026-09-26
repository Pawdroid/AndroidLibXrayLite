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
//
// A socket the protector rejects is never connected: the dial fails instead.
func (x *CoreController) RegisterSocketProtector(protector SocketProtector) error {
	if protector == nil {
		return fmt.Errorf("socket protector is nil")
	}
	// Opened now, while descriptors are plentiful: a rejection must not need a free
	// descriptor, since descriptor exhaustion is exactly what a TUN loop causes.
	inertFd, err := openInertSocket()
	if err != nil {
		return fmt.Errorf("open inert socket for rejected protection: %w", err)
	}

	return internet.RegisterDialerController(protectingDialerController(protector, inertFd))
}

func protectingDialerController(protector SocketProtector, inertFd int) func(network, address string, rawConn syscall.RawConn) error {
	return func(network, address string, rawConn syscall.RawConn) error {
		var protectErr error
		controlErr := rawConn.Control(func(fd uintptr) {
			if protector.Protect(int32(fd)) {
				return
			}
			protectErr = fmt.Errorf("VpnService rejected socket protection for fd %d", fd)
			// xray-core's system dialer only logs controller errors and then binds and
			// connects anyway, which would send this unprotected socket through the TUN and
			// back into the core. Controllers run before bind/connect, so swapping the socket
			// for the inert one here makes that bind/connect fail before anything is sent.
			if err := replaceWithInertSocket(inertFd, int(fd)); err != nil {
				protectErr = fmt.Errorf("%w; disable the unprotected socket: %v", protectErr, err)
			}
		})
		if controlErr != nil {
			return fmt.Errorf("access socket for VPN protection: %w", controlErr)
		}
		return protectErr
	}
}
