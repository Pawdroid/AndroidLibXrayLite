package libv2ray

import (
	"syscall"
	"testing"

	"github.com/xtls/xray-core/transport/internet"
)

type recordingSocketProtector struct {
	fd       int32
	accepted bool
}

func (p *recordingSocketProtector) Protect(fd int32) bool {
	p.fd = fd
	return p.accepted
}

type rawConnStub struct {
	fd uintptr
}

func (r rawConnStub) Control(callback func(uintptr)) error {
	callback(r.fd)
	return nil
}

func (rawConnStub) Read(func(uintptr) bool) error {
	return syscall.EINVAL
}

func (rawConnStub) Write(func(uintptr) bool) error {
	return syscall.EINVAL
}

func TestRegisterSocketProtectorProtectsDialerFileDescriptor(t *testing.T) {
	internet.ControllersLock.Lock()
	previousControllers := internet.Controllers
	internet.Controllers = nil
	internet.ControllersLock.Unlock()
	t.Cleanup(func() {
		internet.ControllersLock.Lock()
		internet.Controllers = previousControllers
		internet.ControllersLock.Unlock()
	})

	protector := &recordingSocketProtector{accepted: true}
	controller := &CoreController{}
	if err := controller.RegisterSocketProtector(protector); err != nil {
		t.Fatalf("register protector: %v", err)
	}
	if len(internet.Controllers) != 1 {
		t.Fatalf("expected one dialer controller, got %d", len(internet.Controllers))
	}
	if err := internet.Controllers[0]("tcp", "example.com:443", rawConnStub{fd: 73}); err != nil {
		t.Fatalf("protect socket: %v", err)
	}
	if protector.fd != 73 {
		t.Fatalf("expected fd 73, got %d", protector.fd)
	}
}

func TestRegisterSocketProtectorReportsRejectedProtection(t *testing.T) {
	internet.ControllersLock.Lock()
	previousControllers := internet.Controllers
	internet.Controllers = nil
	internet.ControllersLock.Unlock()
	t.Cleanup(func() {
		internet.ControllersLock.Lock()
		internet.Controllers = previousControllers
		internet.ControllersLock.Unlock()
	})

	protector := &recordingSocketProtector{accepted: false}
	controller := &CoreController{}
	if err := controller.RegisterSocketProtector(protector); err != nil {
		t.Fatalf("register protector: %v", err)
	}
	if err := internet.Controllers[0]("tcp", "example.com:443", rawConnStub{fd: 91}); err == nil {
		t.Fatal("expected rejected socket protection to return an error")
	}
}
