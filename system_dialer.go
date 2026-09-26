package libv2ray

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	appdns "github.com/xtls/xray-core/app/dns"
	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/common/geodata"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	core "github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/transport/internet"
)

// xray-core keeps a single process-wide system dialer state: the DNS client behind sockopt
// domainStrategy lookups and the outbound manager behind sockopt.dialerProxy. core.New points
// it at whichever instance it is creating, so each MeasureOutboundDelay instance used to take
// it from the running core and leave it on the closed measurement instance.
//
// The running core owns that state. What gets installed is a thin layer over the owner's DNS
// client and outbound manager that also serves the live measurement instances without handing
// them the state: a measurement's dialerProxy tags are rewritten into a scope that only this layer
// resolves (to that measurement's own outbounds), and the server addresses its config pins in DNS
// hosts answer lookups while it runs. With no core running, the newest instance backs the layer,
// as core.New left it.
var (
	systemDialerMu    sync.Mutex
	systemDialerOwner *core.Instance // the running core
	systemDialerBase  *core.Instance // whose DNS client and outbound manager back the layer

	// Read on every dial and lookup, so kept out of systemDialerMu (held across core.New).
	measurementScopes sync.Map // scope name -> *measurementScope
	measurementSeq    atomic.Uint64
)

const measurementScopePrefix = "libv2ray-measurement-"

type measurementScope struct {
	name  string
	obm   outbound.Manager
	hosts map[string][]net.IP
}

// newRunningInstance creates the long-running core instance and makes it the owner of the
// system dialer state.
func newRunningInstance(config *core.Config) (*core.Instance, error) {
	systemDialerMu.Lock()
	defer systemDialerMu.Unlock()

	inst, err := core.New(config)
	if err == nil {
		systemDialerOwner = inst
	}
	// core.New points the dialer at the new instance before it can fail, so reinstall either way.
	installSystemDialerLocked(inst)
	return inst, err
}

// newMeasurementInstance creates a short-lived instance that leaves the system dialer state with
// the running core. dnsApp is the measurement config's DNS app, which is not started; see
// pinnedHosts for what of it is served. release closes the instance and drops its scope.
func newMeasurementInstance(config *core.Config, dnsApp *serial.TypedMessage) (inst *core.Instance, release func(), err error) {
	scope := &measurementScope{
		name:  measurementScopePrefix + strconv.FormatUint(measurementSeq.Add(1), 10) + "/",
		hosts: pinnedHosts(dnsApp),
	}
	scopeDialerProxies(config.Outbound, scope.name)

	systemDialerMu.Lock()
	defer systemDialerMu.Unlock()

	inst, err = core.New(config)
	if err != nil {
		installSystemDialerLocked(nil)
		return nil, nil, err
	}
	scope.obm, _ = inst.GetFeature(outbound.ManagerType()).(outbound.Manager)
	measurementScopes.Store(scope.name, scope)
	installSystemDialerLocked(inst)
	return inst, func() {
		inst.Close()
		measurementScopes.Delete(scope.name)
	}, nil
}

// releaseSystemDialer drops inst's ownership once it is shut down.
func releaseSystemDialer(inst *core.Instance) {
	systemDialerMu.Lock()
	defer systemDialerMu.Unlock()

	if systemDialerOwner == inst {
		systemDialerOwner = nil
	}
}

// installSystemDialerLocked points the system dialer at the layer, backed by the running core, or
// with none running by candidate (the instance core.New just created), else by the previous base.
func installSystemDialerLocked(candidate *core.Instance) {
	switch {
	case systemDialerOwner != nil:
		systemDialerBase = systemDialerOwner
	case candidate != nil:
		systemDialerBase = candidate
	}
	var dnsClient dns.Client
	var obm outbound.Manager
	if systemDialerBase != nil {
		dnsClient, _ = systemDialerBase.GetFeature(dns.ClientType()).(dns.Client)
		obm, _ = systemDialerBase.GetFeature(outbound.ManagerType()).(outbound.Manager)
	}
	internet.InitSystemDialer(&scopedDNSClient{base: dnsClient}, &scopedOutboundManager{base: obm})
}

// scopeDialerProxies rewrites each outbound's sockopt.dialerProxy into scope, so the system
// dialer resolves it among this instance's outbounds instead of the running core's.
func scopeDialerProxies(outbounds []*core.OutboundHandlerConfig, scope string) {
	for _, ob := range outbounds {
		if ob == nil || ob.SenderSettings == nil {
			continue
		}
		msg, err := ob.SenderSettings.GetInstance()
		if err != nil {
			continue
		}
		sender, ok := msg.(*proxyman.SenderConfig)
		if !ok || sender.StreamSettings == nil || sender.StreamSettings.SocketSettings == nil ||
			sender.StreamSettings.SocketSettings.DialerProxy == "" {
			continue
		}
		sender.StreamSettings.SocketSettings.DialerProxy = scope + sender.StreamSettings.SocketSettings.DialerProxy
		ob.SenderSettings = serial.ToTypedMessage(sender)
	}
}

// pinnedHosts returns the full-domain IP hosts of a DNS section that does nothing but pin hosts,
// which is how the app pins speed-test server addresses. A DNS section with its own name servers
// was never applied to measurements and still is not: its hosts would be served to the running
// core's lookups too while the measurement runs.
func pinnedHosts(dnsApp *serial.TypedMessage) map[string][]net.IP {
	if dnsApp == nil {
		return nil
	}
	msg, err := dnsApp.GetInstance()
	if err != nil {
		return nil
	}
	config, ok := msg.(*appdns.Config)
	if !ok || len(config.NameServer) > 0 {
		return nil
	}
	var hosts map[string][]net.IP
	for _, mapping := range config.StaticHosts {
		domain := mapping.GetDomain().GetCustom()
		if domain.GetType() != geodata.Domain_Full || domain.GetValue() == "" || mapping.GetProxiedDomain() != "" {
			continue
		}
		name := strings.ToLower(strings.TrimSuffix(domain.GetValue(), "."))
		for _, ip := range mapping.GetIp() {
			if len(ip) != net.IPv4len && len(ip) != net.IPv6len {
				continue
			}
			if hosts == nil {
				hosts = make(map[string][]net.IP)
			}
			hosts[name] = append(hosts[name], net.IP(ip))
		}
	}
	return hosts
}

func measurementHandler(tag string) outbound.Handler {
	rest := tag[len(measurementScopePrefix):]
	slash := strings.IndexByte(rest, '/')
	if slash < 0 {
		return nil
	}
	value, ok := measurementScopes.Load(tag[:len(measurementScopePrefix)+slash+1])
	if !ok {
		return nil
	}
	scope := value.(*measurementScope)
	if scope.obm == nil {
		return nil
	}
	return scope.obm.GetHandler(rest[slash+1:])
}

func pinnedMeasurementIPs(domain string, option dns.IPOption) []net.IP {
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	var ips []net.IP
	measurementScopes.Range(func(_, value any) bool {
		for _, ip := range value.(*measurementScope).hosts[domain] {
			if isIPv4 := ip.To4() != nil; (isIPv4 && option.IPv4Enable) || (!isIPv4 && option.IPv6Enable) {
				ips = append(ips, ip)
			}
		}
		return len(ips) == 0
	})
	return ips
}

var (
	errNoOutboundManager = errors.New("no outbound manager for the system dialer")
	errNoDNSClient       = errors.New("no DNS client for the system dialer")
)

// scopedOutboundManager is the system dialer's outbound manager (only GetHandler is used there).
type scopedOutboundManager struct {
	base outbound.Manager
}

func (m *scopedOutboundManager) Type() interface{} { return outbound.ManagerType() }
func (m *scopedOutboundManager) Start() error      { return nil }
func (m *scopedOutboundManager) Close() error      { return nil }

func (m *scopedOutboundManager) GetHandler(tag string) outbound.Handler {
	if strings.HasPrefix(tag, measurementScopePrefix) {
		return measurementHandler(tag)
	}
	if m.base == nil {
		return nil
	}
	return m.base.GetHandler(tag)
}

func (m *scopedOutboundManager) GetDefaultHandler() outbound.Handler {
	if m.base == nil {
		return nil
	}
	return m.base.GetDefaultHandler()
}

func (m *scopedOutboundManager) AddHandler(ctx context.Context, handler outbound.Handler) error {
	if m.base == nil {
		return errNoOutboundManager
	}
	return m.base.AddHandler(ctx, handler)
}

func (m *scopedOutboundManager) RemoveHandler(ctx context.Context, tag string) error {
	if m.base == nil {
		return errNoOutboundManager
	}
	return m.base.RemoveHandler(ctx, tag)
}

func (m *scopedOutboundManager) ListHandlers(ctx context.Context) []outbound.Handler {
	if m.base == nil {
		return nil
	}
	return m.base.ListHandlers(ctx)
}

// scopedDNSClient is the system dialer's DNS client: a live measurement's pinned server addresses
// first, then the base instance's DNS client.
type scopedDNSClient struct {
	base dns.Client
}

func (c *scopedDNSClient) Type() interface{} { return dns.ClientType() }
func (c *scopedDNSClient) Start() error      { return nil }
func (c *scopedDNSClient) Close() error      { return nil }

func (c *scopedDNSClient) LookupIP(domain string, option dns.IPOption) ([]net.IP, uint32, error) {
	if ips := pinnedMeasurementIPs(domain, option); len(ips) > 0 {
		return ips, 10, nil // the TTL xray gives static hosts
	}
	if c.base == nil {
		return nil, 0, errNoDNSClient
	}
	return c.base.LookupIP(domain, option)
}
