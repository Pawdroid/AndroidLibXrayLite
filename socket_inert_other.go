//go:build !linux

package libv2ray

import "syscall"

// Host-side (darwin) counterpart of socket_inert_linux.go so the package tests run on the
// build machine.

func openInertSocket() (int, error) {
	fd, err := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return -1, err
	}
	syscall.CloseOnExec(fd)
	if err := syscall.SetNonblock(fd, true); err != nil {
		syscall.Close(fd)
		return -1, err
	}
	return fd, nil
}

func replaceWithInertSocket(inertFd, fd int) error {
	if err := syscall.Dup2(inertFd, fd); err != nil {
		return err
	}
	syscall.CloseOnExec(fd)
	return nil
}
