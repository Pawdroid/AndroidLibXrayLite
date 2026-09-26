package libv2ray

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
)

type stubCallbackHandler struct{}

func (stubCallbackHandler) Startup() int                 { return 0 }
func (stubCallbackHandler) Shutdown() int                { return 0 }
func (stubCallbackHandler) OnEmitStatus(int, string) int { return 0 }

func startTestCore(t *testing.T, config string) *CoreController {
	t.Helper()
	controller := NewCoreController(stubCallbackHandler{})
	if err := controller.StartLoop(config, 0); err != nil {
		t.Fatalf("start core: %v", err)
	}
	t.Cleanup(func() { controller.StopLoop() })
	return controller
}

func freeTCPPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	return port
}

// core.New re-points xray's process-wide system dialer (DNS client for sockopt
// domainStrategy, outbound manager for sockopt.dialerProxy) at the instance being created.
// A delay measurement taken while connected must leave the running core's dialer state in
// place instead of pointing it at the closed measurement instance.
func TestMeasureOutboundDelayKeepsRunningCoreDialerState(t *testing.T) {
	isolateDialerControllers(t)
	startTestCore(t, `{
		"dns": {"hosts": {"running-core.test": "127.0.0.2"}},
		"outbounds": [
			{"protocol": "freedom", "tag": "direct"},
			{"protocol": "blackhole", "tag": "running-only"}
		]
	}`)

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer target.Close()

	if _, err := MeasureOutboundDelay(`{"outbounds": [{"protocol": "freedom", "tag": "proxy"}]}`, target.URL); err != nil {
		t.Fatalf("measure delay: %v", err)
	}

	ips, err := internet.LookupForIP("running-core.test", internet.DomainStrategy_USE_IP, nil)
	if err != nil || len(ips) != 1 || !ips[0].Equal(net.IPv4(127, 0, 0, 2)) {
		t.Fatalf("running core DNS client was replaced: ips=%v err=%v", ips, err)
	}

	conn, err := internet.DialSystem(context.Background(),
		xnet.TCPDestination(xnet.LocalHostIP, xnet.Port(9)),
		&internet.SocketConfig{DialerProxy: "running-only"})
	if err != nil {
		t.Fatalf("running core outbound manager was replaced: %v", err)
	}
	conn.Close()
}

// A failed Start must close what did start; coreInstance is overwritten on the next start and
// anything left running (listeners, goroutines) would leak.
func TestStartLoopClosesInstanceWhenStartFails(t *testing.T) {
	isolateDialerControllers(t)
	busy, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("occupy port: %v", err)
	}
	defer busy.Close()
	busyPort := busy.Addr().(*net.TCPAddr).Port
	startedPort := freeTCPPort(t)

	// Tagged inbounds start before untagged ones, so the first listener is up when the second
	// one fails on the occupied port.
	config := fmt.Sprintf(`{
		"inbounds": [
			{"tag": "started", "listen": "127.0.0.1", "port": %d, "protocol": "socks", "settings": {"udp": false}},
			{"listen": "127.0.0.1", "port": %d, "protocol": "socks", "settings": {"udp": false}}
		],
		"outbounds": [{"protocol": "freedom", "tag": "direct"}]
	}`, startedPort, busyPort)

	controller := NewCoreController(stubCallbackHandler{})
	if err := controller.StartLoop(config, 0); err == nil {
		controller.StopLoop()
		t.Fatal("expected start to fail on the occupied port")
	}
	if controller.IsRunning {
		t.Fatal("controller reports running after a failed start")
	}

	ln, err := net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", startedPort))
	if err != nil {
		t.Fatalf("listener from the failed start is still open: %v", err)
	}
	ln.Close()
}

func noContentServer(t *testing.T) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(server.Close)
	return server
}

// Speed-test configs dial through their own outbounds with sockopt.dialerProxy (fragment, proxy
// chains, subscription previous/next hops). xray resolves that tag in the process-wide outbound
// manager, which belongs to the running core; a measurement taken while connected must still
// reach its own hops, not fail on a tag the running core lacks or ride the running core's
// outbound of the same name.
func TestMeasureOutboundDelayDialsThroughItsOwnDialerProxyWhileConnected(t *testing.T) {
	isolateDialerControllers(t)
	startTestCore(t, `{
		"outbounds": [
			{"protocol": "freedom", "tag": "direct"},
			{"protocol": "blackhole", "tag": "hop"}
		]
	}`)
	target := noContentServer(t)

	if _, err := MeasureOutboundDelay(`{"outbounds": [
		{"protocol": "freedom", "tag": "proxy", "streamSettings": {"sockopt": {"dialerProxy": "hop"}}},
		{"protocol": "freedom", "tag": "hop", "streamSettings": {"sockopt": {"dialerProxy": "hop2"}}},
		{"protocol": "freedom", "tag": "hop2"}
	]}`, target.URL); err != nil {
		t.Fatalf("measure delay through the config's own dialerProxy chain: %v", err)
	}

	// The running core's own dialerProxy tag still resolves in its own outbound manager.
	conn, err := internet.DialSystem(context.Background(),
		xnet.TCPDestination(xnet.LocalHostIP, xnet.Port(9)),
		&internet.SocketConfig{DialerProxy: "hop"})
	if err != nil {
		t.Fatalf("running core outbound manager was replaced: %v", err)
	}
	conn.Close()
}

// Speed-test configs pin their server domains with DNS hosts plus the UseIP dial strategy
// (resolved on the underlying network, since inside our own tunnel the system resolver answers
// from FakeDNS). The measurement must dial the pinned address, with or without a running core,
// and the pin must not outlive the measurement.
func TestMeasureOutboundDelayHonorsPinnedServerHosts(t *testing.T) {
	for _, connected := range []bool{false, true} {
		t.Run(fmt.Sprintf("connected=%v", connected), func(t *testing.T) {
			isolateDialerControllers(t)
			if connected {
				startTestCore(t, `{
					"dns": {"hosts": {"running-core.test": "127.0.0.2"}},
					"outbounds": [{"protocol": "freedom", "tag": "direct"}]
				}`)
			}
			target := noContentServer(t)
			port := target.Listener.Addr().(*net.TCPAddr).Port

			config := fmt.Sprintf(`{
				"dns": {"hosts": {"pinned-node.invalid": "127.0.0.1"}},
				"outbounds": [{
					"protocol": "freedom", "tag": "proxy",
					"settings": {"redirect": "pinned-node.invalid:%d"},
					"streamSettings": {"sockopt": {"domainStrategy": "UseIP"}}
				}]
			}`, port)
			if _, err := MeasureOutboundDelay(config, target.URL); err != nil {
				t.Fatalf("measure delay with a pinned server address: %v", err)
			}

			if ips, err := internet.LookupForIP("pinned-node.invalid", internet.DomainStrategy_USE_IP, nil); err == nil {
				for _, ip := range ips {
					if ip.Equal(net.IPv4(127, 0, 0, 1)) {
						t.Fatalf("the measurement's pinned host outlived it: %v", ips)
					}
				}
			}
			if connected {
				ips, err := internet.LookupForIP("running-core.test", internet.DomainStrategy_USE_IP, nil)
				if err != nil || len(ips) != 1 || !ips[0].Equal(net.IPv4(127, 0, 0, 2)) {
					t.Fatalf("running core DNS client was replaced: ips=%v err=%v", ips, err)
				}
			}
		})
	}
}

// A batch test runs many measurements at once next to the running core; each must resolve its own
// dialerProxy hops and pinned server address, never another measurement's.
//
// Under -race this reports xray-core's own unsynchronized InitSystemDialer globals (written by
// every core.New while other instances dial); the original code reports the same race.
func TestConcurrentMeasurementsKeepTheirOwnDialerState(t *testing.T) {
	isolateDialerControllers(t)
	startTestCore(t, `{"outbounds": [{"protocol": "freedom", "tag": "direct"}, {"protocol": "blackhole", "tag": "hop"}]}`)
	target := noContentServer(t)
	port := target.Listener.Addr().(*net.TCPAddr).Port

	const measurements = 16
	errs := make(chan error, measurements)
	for i := 0; i < measurements; i++ {
		// Odd measurements reach the target only through their own hop; even ones make their hop a
		// blackhole, so resolving another measurement's hop (or the running core's) shows up as a
		// wrong result either way.
		hop := `{"protocol": "freedom", "tag": "hop"}`
		wantOK := i%2 == 1
		if !wantOK {
			hop = `{"protocol": "blackhole", "tag": "hop"}`
		}
		config := fmt.Sprintf(`{
			"dns": {"hosts": {"node-%d.invalid": "127.0.0.1"}},
			"outbounds": [
				{"protocol": "freedom", "tag": "proxy",
				 "settings": {"redirect": "node-%d.invalid:%d"},
				 "streamSettings": {"sockopt": {"domainStrategy": "UseIP", "dialerProxy": "hop"}}},
				%s
			]
		}`, i, i, port, hop)
		go func(i int, wantOK bool) {
			_, err := MeasureOutboundDelay(config, target.URL)
			switch {
			case wantOK && err != nil:
				errs <- fmt.Errorf("measurement %d through its own hop failed: %v", i, err)
			case !wantOK && err == nil:
				errs <- fmt.Errorf("measurement %d succeeded through a hop that is not its own", i)
			default:
				errs <- nil
			}
		}(i, wantOK)
	}
	for i := 0; i < measurements; i++ {
		if err := <-errs; err != nil {
			t.Error(err)
		}
	}
}
