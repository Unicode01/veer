//go:build linux

package netservice

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/bpf"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"
)

const (
	ipv6RAHopLimit             = 255
	ipv6RACurHopLimit          = 64
	ipv6RARouterLifetime       = 1800 * time.Second
	ipv6RAValidLifetime        = 24 * time.Hour
	ipv6RAPreferredLifetime    = 4 * time.Hour
	ipv6RDNSSLifetime          = ipv6RARouterLifetime
	ipv6RAAdvertisementPeriod  = 30 * time.Second
	ipv6RAMinSolicitedInterval = 3 * time.Second
	ipv6RATroubleLogEvery      = 5 * time.Minute
	ipv6RAMaxRDNSSServers      = 8
	// A host keeps an address whose prefix merely drops out of the RAs
	// preferred for the rest of its preferred lifetime, so after the WAN
	// delegates a new prefix it can go on using the old one, which no
	// longer routes. A prefix the interface stops advertising is therefore
	// advertised with zero lifetimes (RFC 9096) for one preferred lifetime:
	// any host that hears an RA in that time deprecates its address, and
	// one that hears none has seen it deprecate on its own.
	ipv6RAStalePrefixRetention = ipv6RAPreferredLifetime
	ipv6RAMaxStalePrefixes     = 16
	ipv6NextHeaderICMPv6       = 58
	icmpv6TypeRouterSolicit    = 133
)

var ipv6AllNodesLinkLocal = net.ParseIP("ff02::1")

type ipv6RouterAdvertiser struct {
	mu     sync.Mutex
	config ipv6AssignmentRAConfig
	// stale holds prefixes this interface no longer has, each with the
	// time until which RAs still deprecate it.
	stale            map[string]time.Time
	stopCh           chan struct{}
	wakeCh           chan struct{}
	rsWakeCh         chan struct{}
	doneCh           chan struct{}
	rsDoneCh         chan struct{}
	rsWake           *serviceWaker
	currentRSFD      int
	rsListeningSince time.Time
	lastIssueText    string
	lastIssueAt      time.Time
	lastIssueLogAt   time.Time
	lastRSIssue      string
	lastRSIssueAt    time.Time
	lastRSIssueLogAt time.Time
	lastRSSeenAt     time.Time
	lastRSSeenLogAt  time.Time
	rsSendPending    bool
	sendCount        uint64
	lastSendAt       time.Time
	lastSendAttempt  time.Time
}

func newIPv6RouterAdvertiser(config ipv6AssignmentRAConfig) *ipv6RouterAdvertiser {
	return &ipv6RouterAdvertiser{
		config:      cloneIPv6AssignmentRAConfig(config),
		stopCh:      make(chan struct{}),
		wakeCh:      make(chan struct{}, 1),
		rsWakeCh:    make(chan struct{}, 1),
		doneCh:      make(chan struct{}),
		rsDoneCh:    make(chan struct{}),
		rsWake:      newServiceWaker(),
		currentRSFD: -1,
	}
}

func (adv *ipv6RouterAdvertiser) start() {
	go adv.run()
	go adv.listenForRouterSolicitations()
}

func cloneIPv6AssignmentRAConfig(config ipv6AssignmentRAConfig) ipv6AssignmentRAConfig {
	config.Prefixes = append([]string(nil), config.Prefixes...)
	config.Routes = append([]string(nil), config.Routes...)
	config.DNSServers = append([]string(nil), config.DNSServers...)
	return config
}

func ipv6AssignmentRAConfigsEqual(a, b ipv6AssignmentRAConfig) bool {
	return a.TargetInterface == b.TargetInterface &&
		a.Managed == b.Managed &&
		slices.Equal(a.Prefixes, b.Prefixes) &&
		slices.Equal(a.Routes, b.Routes) &&
		slices.Equal(a.DNSServers, b.DNSServers)
}

func (adv *ipv6RouterAdvertiser) update(config ipv6AssignmentRAConfig) bool {
	if adv == nil {
		return false
	}
	adv.mu.Lock()
	if ipv6AssignmentRAConfigsEqual(adv.config, config) {
		adv.mu.Unlock()
		return false
	}
	adv.stale = retireIPv6RAPrefixes(adv.stale, adv.config.Prefixes, config.Prefixes, time.Now())
	adv.config = cloneIPv6AssignmentRAConfig(config)
	adv.mu.Unlock()
	adv.trigger()
	return true
}

// adoptStalePrefixes takes over the prefixes an earlier advertiser on the
// same interface stopped with.
func (adv *ipv6RouterAdvertiser) adoptStalePrefixes(stale map[string]time.Time, now time.Time) {
	adv.mu.Lock()
	adv.stale = retireIPv6RAPrefixes(stale, nil, adv.config.Prefixes, now)
	adv.mu.Unlock()
}

// stalePrefixesOnStop returns what the next advertiser on this interface
// must deprecate: everything this one advertised or still deprecates.
func (adv *ipv6RouterAdvertiser) stalePrefixesOnStop(now time.Time) map[string]time.Time {
	adv.mu.Lock()
	defer adv.mu.Unlock()
	return retireIPv6RAPrefixes(adv.stale, adv.config.Prefixes, nil, now)
}

// deprecatedPrefixes lists, in order, the stale prefixes still to deprecate.
func (adv *ipv6RouterAdvertiser) deprecatedPrefixes(now time.Time) []string {
	adv.mu.Lock()
	defer adv.mu.Unlock()
	out := make([]string, 0, len(adv.stale))
	for prefix, until := range adv.stale {
		if now.Before(until) {
			out = append(out, prefix)
		}
	}
	slices.Sort(out)
	return out
}

// retireIPv6RAPrefixes returns the stale set after an interface went from
// advertising previous to advertising current: expired and re-advertised
// prefixes leave it, prefixes no longer advertised join it.
func retireIPv6RAPrefixes(stale map[string]time.Time, previous, current []string, now time.Time) map[string]time.Time {
	advertised := make(map[string]struct{}, len(current))
	for _, prefix := range current {
		if key, ok := canonicalIPv6RAPrefix(prefix); ok {
			advertised[key] = struct{}{}
		}
	}
	out := make(map[string]time.Time, len(stale)+len(previous))
	for prefix, until := range stale {
		if _, ok := advertised[prefix]; !ok && now.Before(until) {
			out[prefix] = until
		}
	}
	for _, prefix := range previous {
		key, ok := canonicalIPv6RAPrefix(prefix)
		if !ok {
			continue
		}
		if _, ok := advertised[key]; !ok {
			out[key] = now.Add(ipv6RAStalePrefixRetention)
		}
	}
	for len(out) > ipv6RAMaxStalePrefixes {
		oldest := ""
		for prefix, until := range out {
			if oldest == "" || until.Before(out[oldest]) || (until.Equal(out[oldest]) && prefix < oldest) {
				oldest = prefix
			}
		}
		delete(out, oldest)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func canonicalIPv6RAPrefix(text string) (string, bool) {
	_, prefix, err := net.ParseCIDR(strings.TrimSpace(text))
	if err != nil || prefix == nil || prefix.IP.To4() != nil {
		return "", false
	}
	return prefix.String(), true
}

func (adv *ipv6RouterAdvertiser) trigger() {
	if adv == nil {
		return
	}
	select {
	case adv.wakeCh <- struct{}{}:
	default:
	}
}

func (adv *ipv6RouterAdvertiser) triggerRouterSolicitation() bool {
	if adv == nil {
		return false
	}
	adv.mu.Lock()
	if adv.rsSendPending {
		adv.mu.Unlock()
		return false
	}
	adv.rsSendPending = true
	adv.mu.Unlock()
	select {
	case adv.rsWakeCh <- struct{}{}:
		return true
	default:
		adv.clearRouterSolicitationPending()
		return false
	}
}

func (adv *ipv6RouterAdvertiser) clearRouterSolicitationPending() {
	adv.mu.Lock()
	adv.rsSendPending = false
	adv.mu.Unlock()
}

func (adv *ipv6RouterAdvertiser) routerSolicitationDelay(now time.Time) time.Duration {
	adv.mu.Lock()
	lastAttempt := adv.lastSendAttempt
	adv.mu.Unlock()
	if lastAttempt.IsZero() || !now.Before(lastAttempt.Add(ipv6RAMinSolicitedInterval)) {
		return 0
	}
	return lastAttempt.Add(ipv6RAMinSolicitedInterval).Sub(now)
}

func (adv *ipv6RouterAdvertiser) stop() {
	if adv == nil {
		return
	}
	// The solicitation socket belongs to listenForRouterSolicitations, which
	// closes it on its way out; see serviceWaker for why stop() must not
	// close it itself.
	close(adv.stopCh)
	adv.rsWake.wake()
	<-adv.doneCh
	<-adv.rsDoneCh
	adv.rsWake.close()
}

func (adv *ipv6RouterAdvertiser) snapshot() ipv6AssignmentRAConfig {
	adv.mu.Lock()
	defer adv.mu.Unlock()
	return cloneIPv6AssignmentRAConfig(adv.config)
}

func (adv *ipv6RouterAdvertiser) run() {
	defer close(adv.doneCh)

	ticker := time.NewTicker(ipv6RAAdvertisementPeriod)
	defer ticker.Stop()
	var rsTimer *time.Timer
	var rsTimerCh <-chan time.Time
	stopRSTimer := func() {
		if rsTimer == nil {
			return
		}
		if !rsTimer.Stop() {
			select {
			case <-rsTimer.C:
			default:
			}
		}
		rsTimerCh = nil
	}
	defer stopRSTimer()
	completePendingRS := func() {
		stopRSTimer()
		select {
		case <-adv.rsWakeCh:
		default:
		}
		adv.clearRouterSolicitationPending()
	}
	schedulePendingRS := func(now time.Time) bool {
		delay := adv.routerSolicitationDelay(now)
		if delay <= 0 {
			adv.send()
			adv.clearRouterSolicitationPending()
			return false
		}
		if rsTimer == nil {
			rsTimer = time.NewTimer(delay)
		} else {
			stopRSTimer()
			rsTimer.Reset(delay)
		}
		rsTimerCh = rsTimer.C
		return true
	}

	adv.send()
	for {
		select {
		case <-adv.stopCh:
			return
		case <-adv.wakeCh:
			adv.send()
			completePendingRS()
		case <-adv.rsWakeCh:
			schedulePendingRS(time.Now())
		case now := <-rsTimerCh:
			schedulePendingRS(now)
		case <-ticker.C:
			adv.send()
			completePendingRS()
		}
	}
}

func (adv *ipv6RouterAdvertiser) listenForRouterSolicitations() {
	defer close(adv.rsDoneCh)

	buf := make([]byte, 2048)
	for {
		config := adv.snapshot()
		state, fd, err := openIPv6RouterSolicitationSocket(config)
		if err != nil {
			if isLinkGoneOrDownError(err) {
				adv.noteRouterSolicitationIssue(fmt.Sprintf("open socket: %v", err))
			} else {
				adv.logRouterSolicitationIssue(fmt.Sprintf("open socket: %v", err))
			}
			select {
			case <-adv.stopCh:
				return
			case <-time.After(2 * time.Second):
				continue
			}
		}

		func() {
			adv.mu.Lock()
			adv.currentRSFD = fd
			adv.rsListeningSince = time.Now()
			adv.lastRSIssue = ""
			adv.lastRSIssueAt = time.Time{}
			adv.mu.Unlock()
			defer unix.Close(fd)
			defer func() {
				adv.mu.Lock()
				if adv.currentRSFD == fd {
					adv.currentRSFD = -1
				}
				adv.mu.Unlock()
			}()
			var interfaces interfaceCheckGate
			for {
				select {
				case <-adv.stopCh:
					return
				default:
				}

				// Wait here, not in a blocking recvfrom, so that stop() can
				// end the wait without closing the socket.
				readable, woken, err := adv.rsWake.waitReadable(fd, 2*time.Second)
				if woken {
					return
				}
				if err == nil && !readable {
					err = unix.EAGAIN
				}
				n := 0
				if err == nil {
					n, _, err = unix.Recvfrom(fd, buf, unix.MSG_DONTWAIT)
				}
				if err != nil {
					if errors.Is(err, unix.EINTR) {
						select {
						case <-adv.stopCh:
							return
						default:
						}
						continue
					}
					if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) {
						if interfaces.run(time.Now(), func() bool { return routerSolicitationSocketNeedsReopen(state) }) {
							return
						}
						continue
					}
					if isLinkGoneOrDownError(err) {
						// The interface went down or away, as a guest's tap
						// does when the guest stops; the socket is reopened
						// once it is back. Expected, so not logged.
						adv.noteRouterSolicitationIssue(fmt.Sprintf("read: %v", err))
						return
					}
					adv.logRouterSolicitationIssue(fmt.Sprintf("read: %v", err))
					return
				}
				if isIPv6RouterSolicitationFrame(buf[:n]) {
					now := time.Now()
					adv.mu.Lock()
					adv.lastRSSeenAt = now
					shouldLog := adv.lastRSSeenLogAt.IsZero() || now.Sub(adv.lastRSSeenLogAt) >= time.Second
					if shouldLog {
						adv.lastRSSeenLogAt = now
					}
					adv.lastRSIssue = ""
					adv.lastRSIssueAt = time.Time{}
					adv.mu.Unlock()
					if shouldLog {
						log.Printf("ipv6 assignment router solicitation received on %s", state.IfName)
					}
					adv.triggerRouterSolicitation()
				}
			}
		}()
		select {
		case <-adv.stopCh:
			return
		default:
		}
	}
}

// isLinkGoneOrDownError reports whether a socket operation failed because its
// interface went down or was removed. RA and DHCPv6 only run on interfaces
// that existed when their assignment was applied (a gone target leaves the
// assignment dormant), so this is a guest stopping or restarting, not a
// misconfiguration, and the next reconcile stops or resumes the service.
func isLinkGoneOrDownError(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, unix.ENETDOWN) || errors.Is(err, unix.ENXIO) || errors.Is(err, unix.ENODEV) ||
		strings.Contains(err.Error(), "no such network interface")
}

// noteRouterSolicitationIssue records an issue for the runtime status without
// logging it.
func (adv *ipv6RouterAdvertiser) noteRouterSolicitationIssue(text string) {
	if adv == nil {
		return
	}
	adv.mu.Lock()
	adv.lastRSIssue = text
	adv.lastRSIssueAt = time.Now()
	adv.mu.Unlock()
}

func (adv *ipv6RouterAdvertiser) logRouterSolicitationIssue(text string) {
	if adv == nil {
		return
	}
	now := time.Now()
	adv.mu.Lock()
	adv.lastRSIssue = text
	adv.lastRSIssueAt = now
	shouldLog := adv.lastRSIssueLogAt.IsZero() || now.Sub(adv.lastRSIssueLogAt) >= ipv6RATroubleLogEvery
	if shouldLog {
		adv.lastRSIssueLogAt = now
	}
	targetInterface := adv.config.TargetInterface
	adv.mu.Unlock()
	if shouldLog {
		log.Printf("ipv6 assignment router solicitation listener on %s: %s", targetInterface, text)
	}
}

func (adv *ipv6RouterAdvertiser) send() {
	config := adv.snapshot()
	deprecated := adv.deprecatedPrefixes(time.Now())
	adv.mu.Lock()
	adv.lastSendAttempt = time.Now()
	adv.mu.Unlock()
	if err := sendIPv6RouterAdvertisement(config, deprecated); err != nil {
		now := time.Now()
		text := err.Error()
		adv.mu.Lock()
		adv.lastIssueText = text
		adv.lastIssueAt = now
		shouldLog := !isLinkGoneOrDownError(err) && (adv.lastIssueLogAt.IsZero() || now.Sub(adv.lastIssueLogAt) >= ipv6RATroubleLogEvery)
		if shouldLog {
			adv.lastIssueLogAt = now
		}
		adv.mu.Unlock()
		if shouldLog {
			log.Printf("ipv6 assignment router advertisement on %s: %v", config.TargetInterface, err)
		}
		return
	}
	adv.mu.Lock()
	adv.lastIssueText = ""
	adv.lastIssueAt = time.Time{}
	adv.sendCount++
	adv.lastSendAt = time.Now()
	adv.mu.Unlock()
}

type ipv6RouterAdvertisementRuntimeState struct {
	Status    string
	Detail    string
	SendCount uint64
}

func (adv *ipv6RouterAdvertiser) snapshotStatus() ipv6RouterAdvertisementRuntimeState {
	if adv == nil {
		return ipv6RouterAdvertisementRuntimeState{}
	}

	adv.mu.Lock()
	sendCount := adv.sendCount
	lastSendAt := adv.lastSendAt
	lastIssueText := adv.lastIssueText
	lastIssueAt := adv.lastIssueAt
	lastRSIssue := adv.lastRSIssue
	lastRSIssueAt := adv.lastRSIssueAt
	lastRSSeenAt := adv.lastRSSeenAt
	listening := adv.currentRSFD >= 0
	rsListeningSince := adv.rsListeningSince
	adv.mu.Unlock()

	sendHealthyAt := lastSendAt
	rsHealthyAt := rsListeningSince
	if lastRSSeenAt.After(rsHealthyAt) {
		rsHealthyAt = lastRSSeenAt
	}

	state := ipv6RouterAdvertisementRuntimeState{SendCount: sendCount}
	switch {
	case lastIssueText != "" && lastIssueAt.After(sendHealthyAt):
		state.Status = "error"
		state.Detail = lastIssueText
	case lastRSIssue != "" && lastRSIssueAt.After(rsHealthyAt):
		state.Status = "draining"
		state.Detail = "router solicitation listener: " + lastRSIssue
	case listening || !lastSendAt.IsZero():
		state.Status = "running"
		state.Detail = fmt.Sprintf("router advertisements active (sent=%d)", sendCount)
	default:
		state.Status = "draining"
		state.Detail = "waiting for router advertisement runtime"
	}
	return state
}

type ipv6RouterSolicitationState struct {
	IfIndex int
	IfName  string
}

type ipv6RouterAdvertisementState struct {
	IfIndex int
	IfName  string
	MTU     int
	MAC     net.HardwareAddr
	SrcIP   net.IP
	DstIP   net.IP
	Config  ipv6AssignmentRAConfig
	// Deprecated prefixes go out with zero lifetimes.
	Deprecated []string
}

func resolveIPv6RouterAdvertisementState(config ipv6AssignmentRAConfig) (ipv6RouterAdvertisementState, error) {
	iface, err := net.InterfaceByName(config.TargetInterface)
	if err != nil {
		return ipv6RouterAdvertisementState{}, err
	}
	if iface == nil || iface.Index <= 0 {
		return ipv6RouterAdvertisementState{}, fmt.Errorf("interface %q is unavailable", config.TargetInterface)
	}
	identity, err := resolveIPv6ControlIdentity(config.TargetInterface)
	if err != nil {
		return ipv6RouterAdvertisementState{}, err
	}
	return ipv6RouterAdvertisementState{
		IfIndex: iface.Index,
		IfName:  iface.Name,
		MTU:     iface.MTU,
		MAC:     append(net.HardwareAddr(nil), identity.SourceMAC...),
		SrcIP:   append(net.IP(nil), identity.SourceIP...),
		DstIP:   append(net.IP(nil), ipv6AllNodesLinkLocal.To16()...),
		Config: ipv6AssignmentRAConfig{
			TargetInterface: config.TargetInterface,
			Managed:         config.Managed,
			Prefixes:        append([]string(nil), config.Prefixes...),
			Routes:          append([]string(nil), config.Routes...),
		},
	}, nil
}

func selectIPv6LinkLocalAddress(iface net.Interface) (net.IP, error) {
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, err
	}
	for _, raw := range addrs {
		ipNet, ok := raw.(*net.IPNet)
		if !ok || ipNet == nil {
			continue
		}
		ip := ipNet.IP.To16()
		if ip == nil || ip.To4() != nil || !ip.IsLinkLocalUnicast() {
			continue
		}
		return append(net.IP(nil), ip...), nil
	}
	return nil, fmt.Errorf("interface %q has no IPv6 link-local address yet", iface.Name)
}

func openIPv6RouterSolicitationSocket(config ipv6AssignmentRAConfig) (ipv6RouterSolicitationState, int, error) {
	iface, fd, err := openIPv6PacketListenerSocket(config.TargetInterface, 2*time.Second, buildIPv6RouterSolicitationSocketFilter())
	if err != nil {
		return ipv6RouterSolicitationState{}, -1, err
	}
	return ipv6RouterSolicitationState{
		IfIndex: iface.Index,
		IfName:  iface.Name,
	}, fd, nil
}

func buildIPv6RouterSolicitationSocketFilter() []bpf.Instruction {
	return buildPacketSocketEqualityFilter([]packetSocketEqualityCheck{
		{Offset: packetSocketEtherTypeOffset, Size: 2, Value: 0x86dd},
		{Offset: packetSocketIPv6NextHeaderOffset, Size: 1, Value: ipv6NextHeaderICMPv6},
		{Offset: packetSocketIPv6HopLimitOffset, Size: 1, Value: ipv6RAHopLimit},
		{Offset: packetSocketIPv6ICMPTypeOffset, Size: 1, Value: icmpv6TypeRouterSolicit},
	})
}

func routerSolicitationSocketNeedsReopen(state ipv6RouterSolicitationState) bool {
	if state.IfName == "" {
		return false
	}
	iface, err := interfaceByName(state.IfName)
	if err != nil || iface == nil || iface.Index <= 0 {
		return true
	}
	return iface.Index != state.IfIndex
}

func isIPv6RouterSolicitationFrame(frame []byte) bool {
	if len(frame) < 14+40+8 {
		return false
	}
	if binary.BigEndian.Uint16(frame[12:14]) != 0x86dd {
		return false
	}
	ipv6Header := frame[14:]
	if version := ipv6Header[0] >> 4; version != 6 {
		return false
	}
	if ipv6Header[6] != ipv6NextHeaderICMPv6 {
		return false
	}
	if ipv6Header[7] != ipv6RAHopLimit {
		return false
	}
	payloadLen := int(binary.BigEndian.Uint16(ipv6Header[4:6]))
	if payloadLen < 8 || payloadLen > len(ipv6Header)-40 {
		return false
	}
	icmp := ipv6Header[40 : 40+payloadLen]
	return len(icmp) >= 8 && icmp[0] == icmpv6TypeRouterSolicit && icmp[1] == 0
}

func sendIPv6RouterAdvertisement(config ipv6AssignmentRAConfig, deprecated []string) error {
	state, err := resolveIPv6RouterAdvertisementState(config)
	if err != nil {
		return err
	}
	state.Deprecated = deprecated
	payload, err := buildIPv6RouterAdvertisementPayload(state)
	if err != nil {
		return err
	}
	frame, err := buildIPv6RouterAdvertisementFrame(state, payload)
	if err != nil {
		return err
	}
	return sendIPv6RouterAdvertisementFrame(state, frame)
}

func buildIPv6RouterAdvertisementPayload(state ipv6RouterAdvertisementState) ([]byte, error) {
	body := make([]byte, 12)
	body[0] = ipv6RACurHopLimit
	if state.Config.Managed {
		body[1] |= 0x80
	}
	binary.BigEndian.PutUint16(body[2:4], uint16(ipv6RARouterLifetime/time.Second))
	for _, prefixText := range state.Config.Prefixes {
		_, prefix, err := net.ParseCIDR(prefixText)
		if err != nil || prefix == nil {
			return nil, fmt.Errorf("invalid router advertisement prefix %q", prefixText)
		}
		ones, bits := prefix.Mask.Size()
		if ones != 64 || bits != 128 {
			return nil, fmt.Errorf("router advertisements require /64 prefixes, got %q", prefixText)
		}
		body = append(body, buildIPv6PrefixInfoOption(prefix, ipv6RAValidLifetime, ipv6RAPreferredLifetime)...)
	}
	for _, prefixText := range state.Deprecated {
		// A valid lifetime of 0 only shortens a host's longer remaining
		// one to two hours (RFC 4862 5.5.3); the preferred lifetime of 0
		// takes effect at once.
		_, prefix, err := net.ParseCIDR(prefixText)
		if err != nil || prefix == nil {
			continue
		}
		if ones, bits := prefix.Mask.Size(); ones != 64 || bits != 128 {
			continue
		}
		body = append(body, buildIPv6PrefixInfoOption(prefix, 0, 0)...)
	}
	for _, routeText := range state.Config.Routes {
		_, route, err := net.ParseCIDR(routeText)
		if err != nil || route == nil {
			return nil, fmt.Errorf("invalid router advertisement route %q", routeText)
		}
		body = append(body, buildIPv6RouteInfoOption(route, ipv6RARouterLifetime)...)
	}
	if len(state.Config.DNSServers) > 0 {
		option, err := buildIPv6RDNSSOption(state.Config.DNSServers, ipv6RDNSSLifetime)
		if err != nil {
			return nil, err
		}
		body = append(body, option...)
	}
	if len(state.MAC) >= 6 {
		body = append(body, buildIPv6SourceLLAOption(state.MAC)...)
	}
	if state.MTU > 0 {
		body = append(body, buildIPv6MTUOption(state.MTU)...)
	}
	return (&icmp.Message{
		Type: ipv6.ICMPTypeRouterAdvertisement,
		Code: 0,
		Body: &icmp.RawBody{Data: body},
	}).Marshal(icmp.IPv6PseudoHeader(state.SrcIP, state.DstIP))
}

func buildIPv6RouterAdvertisementFrame(state ipv6RouterAdvertisementState, payload []byte) ([]byte, error) {
	if len(state.MAC) < 6 {
		return nil, fmt.Errorf("interface %q has no usable ethernet address", state.IfName)
	}
	if len(payload) > 0xffff {
		return nil, fmt.Errorf("router advertisement payload too large: %d", len(payload))
	}

	frame := make([]byte, 14+40+len(payload))
	copy(frame[0:6], []byte{0x33, 0x33, 0x00, 0x00, 0x00, 0x01})
	copy(frame[6:12], state.MAC[:6])
	binary.BigEndian.PutUint16(frame[12:14], 0x86dd)

	ipv6Header := frame[14 : 14+40]
	ipv6Header[0] = 0x60
	binary.BigEndian.PutUint16(ipv6Header[4:6], uint16(len(payload)))
	ipv6Header[6] = 58
	ipv6Header[7] = ipv6RAHopLimit
	copy(ipv6Header[8:24], state.SrcIP.To16())
	copy(ipv6Header[24:40], state.DstIP.To16())

	copy(frame[14+40:], payload)
	return frame, nil
}

func sendIPv6RouterAdvertisementFrame(state ipv6RouterAdvertisementState, frame []byte) error {
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htonsUnix(unix.ETH_P_IPV6)))
	if err != nil {
		return err
	}
	defer unix.Close(fd)

	var addr [8]byte
	copy(addr[:], []byte{0x33, 0x33, 0x00, 0x00, 0x00, 0x01})
	return unix.Sendto(fd, frame, 0, &unix.SockaddrLinklayer{
		Ifindex:  state.IfIndex,
		Protocol: htonsUnix(unix.ETH_P_IPV6),
		Halen:    6,
		Addr:     addr,
	})
}

func htonsUnix(v uint16) uint16 {
	return (v<<8)&0xff00 | v>>8
}

func buildIPv6PrefixInfoOption(prefix *net.IPNet, validLifetime, preferredLifetime time.Duration) []byte {
	option := make([]byte, 32)
	option[0] = 3
	option[1] = 4
	option[2] = 64
	option[3] = 0xc0
	binary.BigEndian.PutUint32(option[4:8], uint32(validLifetime/time.Second))
	binary.BigEndian.PutUint32(option[8:12], uint32(preferredLifetime/time.Second))
	copy(option[16:32], prefix.IP.To16())
	return option
}

func buildIPv6RouteInfoOption(prefix *net.IPNet, lifetime time.Duration) []byte {
	ones, bits := prefix.Mask.Size()
	if bits != 128 || ones < 0 {
		return nil
	}

	prefixBytes := 0
	switch {
	case ones == 0:
		prefixBytes = 0
	case ones <= 64:
		prefixBytes = 8
	default:
		prefixBytes = 16
	}

	optionLen := 8 + prefixBytes
	option := make([]byte, optionLen)
	option[0] = 24
	option[1] = byte(optionLen / 8)
	option[2] = byte(ones)
	binary.BigEndian.PutUint32(option[4:8], uint32(lifetime/time.Second))
	if prefixBytes > 0 {
		copy(option[8:], prefix.IP.To16()[:prefixBytes])
	}
	return option
}

func buildIPv6RDNSSOption(servers []string, lifetime time.Duration) ([]byte, error) {
	if len(servers) == 0 {
		return nil, nil
	}
	if len(servers) > ipv6RAMaxRDNSSServers {
		return nil, fmt.Errorf("router advertisement cannot contain more than %d DNS servers", ipv6RAMaxRDNSSServers)
	}
	option := make([]byte, 8+16*len(servers))
	option[0] = 25
	option[1] = byte(len(option) / 8)
	binary.BigEndian.PutUint32(option[4:8], uint32(lifetime/time.Second))
	for i, server := range servers {
		ip := net.ParseIP(server)
		if ip == nil || ip.To4() != nil || ip.To16() == nil {
			return nil, fmt.Errorf("invalid router advertisement DNS server %q", server)
		}
		copy(option[8+i*16:8+(i+1)*16], ip.To16())
	}
	return option, nil
}

func buildIPv6SourceLLAOption(mac net.HardwareAddr) []byte {
	option := make([]byte, 8)
	option[0] = 1
	option[1] = 1
	copy(option[2:], mac)
	return option
}

func buildIPv6MTUOption(mtu int) []byte {
	option := make([]byte, 8)
	option[0] = 5
	option[1] = 1
	binary.BigEndian.PutUint32(option[4:8], uint32(mtu))
	return option
}
