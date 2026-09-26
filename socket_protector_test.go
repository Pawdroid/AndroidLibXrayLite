package libv2ray

import (
	"context"
	"net"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
)

type recordingSocketProtector struct {
	fd       atomic.Int32
	calls    atomic.Int32
	accepted bool
}

func (p *recordingSocketProtector) Protect(fd int32) bool {
	p.fd.Store(fd)
	p.calls.Add(1)
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

// isolateDialerControllers gives the test an empty process-wide controller list and restores
// the previous one afterwards.
func isolateDialerControllers(t *testing.T) {
	t.Helper()
	internet.ControllersLock.Lock()
	previousControllers := internet.Controllers
	internet.Controllers = nil
	internet.ControllersLock.Unlock()
	t.Cleanup(func() {
		internet.ControllersLock.Lock()
		internet.Controllers = previousControllers
		internet.ControllersLock.Unlock()
	})
}

func registerTestProtector(t *testing.T, accepted bool) *recordingSocketProtector {
	t.Helper()
	isolateDialerControllers(t)
	protector := &recordingSocketProtector{accepted: accepted}
	if err := (&CoreController{}).RegisterSocketProtector(protector); err != nil {
		t.Fatalf("register protector: %v", err)
	}
	return protector
}

func listenTCP(t *testing.T) *net.TCPListener {
	t.Helper()
	ln, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen tcp: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	return ln
}

func listenUDP(t *testing.T) *net.UDPConn {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

func tcpDestination(ln *net.TCPListener) xnet.Destination {
	return xnet.TCPDestination(xnet.LocalHostIP, xnet.Port(ln.Addr().(*net.TCPAddr).Port))
}

func udpDestination(conn *net.UDPConn) xnet.Destination {
	return xnet.UDPDestination(xnet.LocalHostIP, xnet.Port(conn.LocalAddr().(*net.UDPAddr).Port))
}

func openFileDescriptorCount() int {
	count := 0
	var stat syscall.Stat_t
	for fd := 0; fd < 4096; fd++ {
		if syscall.Fstat(fd, &stat) == nil {
			count++
		}
	}
	return count
}

func TestRegisterSocketProtectorProtectsDialerFileDescriptor(t *testing.T) {
	protector := registerTestProtector(t, true)
	if len(internet.Controllers) != 1 {
		t.Fatalf("expected one dialer controller, got %d", len(internet.Controllers))
	}
	if err := internet.Controllers[0]("tcp", "example.com:443", rawConnStub{fd: 73}); err != nil {
		t.Fatalf("protect socket: %v", err)
	}
	if got := protector.fd.Load(); got != 73 {
		t.Fatalf("expected fd 73, got %d", got)
	}
}

func TestRegisterSocketProtectorRejectsNilProtector(t *testing.T) {
	isolateDialerControllers(t)
	if err := (&CoreController{}).RegisterSocketProtector(nil); err == nil {
		t.Fatal("expected a nil protector to be rejected")
	}
	if len(internet.Controllers) != 0 {
		t.Fatalf("expected no dialer controller, got %d", len(internet.Controllers))
	}
}

func TestProtectedTCPDialConnects(t *testing.T) {
	protector := registerTestProtector(t, true)
	ln := listenTCP(t)

	conn, err := internet.DialSystem(context.Background(), tcpDestination(ln), nil)
	if err != nil {
		t.Fatalf("dial with accepted protection: %v", err)
	}
	defer conn.Close()

	ln.SetDeadline(time.Now().Add(2 * time.Second))
	accepted, err := ln.Accept()
	if err != nil {
		t.Fatalf("listener saw no connection: %v", err)
	}
	accepted.Close()
	if protector.calls.Load() == 0 {
		t.Fatal("protector was not consulted")
	}
}

// xray-core's system dialer only logs controller errors, so returning an error alone would
// still connect the unprotected socket through the TUN. The dial itself must fail, and no
// connection attempt may leave the socket.
func TestRejectedProtectionFailsTCPDialBeforeConnecting(t *testing.T) {
	protector := registerTestProtector(t, false)
	ln := listenTCP(t)

	conn, err := internet.DialSystem(context.Background(), tcpDestination(ln), nil)
	if err == nil {
		conn.Close()
		t.Fatal("expected the dial to fail when VPN protection is rejected")
	}
	t.Logf("rejected TCP dial: %v", err)
	if protector.calls.Load() == 0 {
		t.Fatal("protector was not consulted")
	}

	ln.SetDeadline(time.Now().Add(300 * time.Millisecond))
	if accepted, err := ln.Accept(); err == nil {
		accepted.Close()
		t.Fatal("the unprotected socket reached the destination")
	}
}

func TestRejectedProtectionFailsUDPDialBeforeSending(t *testing.T) {
	protector := registerTestProtector(t, false)
	server := listenUDP(t)

	conn, err := internet.DialSystem(context.Background(), udpDestination(server), nil)
	if err == nil {
		conn.Write([]byte("leak"))
		conn.Close()
		t.Fatal("expected the UDP dial to fail when VPN protection is rejected")
	}
	t.Logf("rejected UDP dial: %v", err)
	if protector.calls.Load() == 0 {
		t.Fatal("protector was not consulted")
	}

	server.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	buf := make([]byte, 16)
	if n, _, err := server.ReadFrom(buf); err == nil {
		t.Fatalf("the unprotected socket sent %q", buf[:n])
	}
}

func TestProtectedUDPDialSends(t *testing.T) {
	registerTestProtector(t, true)
	server := listenUDP(t)

	conn, err := internet.DialSystem(context.Background(), udpDestination(server), nil)
	if err != nil {
		t.Fatalf("dial with accepted protection: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("ok")); err != nil {
		t.Fatalf("write: %v", err)
	}

	server.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 16)
	n, _, err := server.ReadFrom(buf)
	if err != nil || string(buf[:n]) != "ok" {
		t.Fatalf("expected datagram \"ok\", got %q, %v", buf[:n], err)
	}
}

func TestRejectedProtectionDoesNotLeakFileDescriptors(t *testing.T) {
	registerTestProtector(t, false)
	ln := listenTCP(t)
	server := listenUDP(t)

	// Warm up anything the first dial allocates lazily.
	if conn, err := internet.DialSystem(context.Background(), tcpDestination(ln), nil); err == nil {
		conn.Close()
	}
	before := openFileDescriptorCount()
	for i := 0; i < 64; i++ {
		if conn, err := internet.DialSystem(context.Background(), tcpDestination(ln), nil); err == nil {
			conn.Close()
			t.Fatal("expected rejected TCP dial to fail")
		}
		if conn, err := internet.DialSystem(context.Background(), udpDestination(server), nil); err == nil {
			conn.Close()
			t.Fatal("expected rejected UDP dial to fail")
		}
	}
	if after := openFileDescriptorCount(); after > before+2 {
		t.Fatalf("rejected dials leaked file descriptors: %d before, %d after", before, after)
	}
}
