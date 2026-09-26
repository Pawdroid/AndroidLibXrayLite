//go:build linux

package libv2ray

import "syscall"

// openInertSocket returns a Unix datagram socket. Binding or connecting it to an inet
// address fails with EINVAL, so a dialer socket replaced by it can never send anything.
func openInertSocket() (int, error) {
	return syscall.Socket(syscall.AF_UNIX, syscall.SOCK_DGRAM|syscall.SOCK_NONBLOCK|syscall.SOCK_CLOEXEC, 0)
}

// replaceWithInertSocket atomically makes fd refer to the inert socket, closing the socket fd
// referred to. The descriptor number stays owned by the dialer, which closes it after its
// bind/connect fails, so no other goroutine can be handed that number in between.
func replaceWithInertSocket(inertFd, fd int) error {
	return syscall.Dup3(inertFd, fd, syscall.O_CLOEXEC)
}
