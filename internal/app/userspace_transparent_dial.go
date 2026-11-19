package app

import (
	"net"
	"sync"
	"time"
)

// A transparent user space forward dials its backend from the client's own
// address. Two things around that dial decide whether the backend's answers
// come back to it:
//
//   - A client in the backend's own network (a guest reaching a guest on the
//     same bridge through the host's public address) would be answered
//     directly, past this host, and drop the answer it never asked for. Such
//     a client is dialled from this host's address instead, as a kernel
//     hairpin forward does.
//   - SO_BINDTODEVICE on the dial pins it to the outbound interface. When the
//     route to the backend leaves by that interface anyway the binding adds
//     nothing, and it hides the socket from lookups made on another device: a
//     backend behind egress NAT answers through its bridge port, where the TC
//     program must find this socket to leave the answer to the host (see
//     egress_nat_reply_to_host_socket_v4). The binding is kept only where it
//     changes the route.

type userspaceTransparentDialPlan struct {
	transparent bool   // dial from the client's address
	bindIface   string // SO_BINDTODEVICE for the dial; "" for none
}

const userspaceDialLookupTTL = 5 * time.Second

var (
	userspaceRouteIfaceLookup  = lookupUserspaceRouteIface
	userspaceIfacePrefixLookup = lookupUserspaceIfacePrefixes
	userspaceDialLookups       = newUserspaceDialLookupCache()
)

func planUserspaceTransparentDial(client net.IP, backend net.IP, outIface string) userspaceTransparentDialPlan {
	routeIface := ""
	if backend != nil {
		routeIface = userspaceDialLookups.routeIface(backend)
	}
	via := outIface
	if via == "" {
		via = routeIface
	}
	if via != "" && client != nil && backend != nil {
		for _, prefix := range userspaceDialLookups.ifacePrefixes(via) {
			if prefix.Contains(client) && prefix.Contains(backend) {
				return userspaceTransparentDialPlan{transparent: false, bindIface: outIface}
			}
		}
	}
	bind := outIface
	if outIface != "" && routeIface == outIface {
		bind = ""
	}
	return userspaceTransparentDialPlan{transparent: true, bindIface: bind}
}

// configureTransparentTCPDialer sets dialer up for a transparent forward of
// client's connection to backend and returns the network to dial.
func configureTransparentTCPDialer(dialer *net.Dialer, client net.IP, backend string, outIface string) (string, error) {
	backendIP := net.ParseIP(backend)
	if host, _, err := net.SplitHostPort(backend); err == nil {
		backendIP = net.ParseIP(host)
	}
	clientIP := client.To4()
	if clientIP == nil {
		clientIP = client
	}
	plan := planUserspaceTransparentDial(clientIP, backendIP, outIface)
	if !plan.transparent {
		if err := configureOutboundTCPDialer(dialer, plan.bindIface, ""); err != nil {
			return "", err
		}
		return "tcp", nil
	}
	dialer.LocalAddr = &net.TCPAddr{IP: clientIP, Port: 0}
	dialer.Control = controlTransparent(clientIP, plan.bindIface)
	return "tcp4", nil
}

type userspaceDialLookupCache struct {
	mu       sync.Mutex
	routes   map[string]userspaceCachedRoute
	prefixes map[string]userspaceCachedPrefixes
}

type userspaceCachedRoute struct {
	iface   string
	expires time.Time
}

type userspaceCachedPrefixes struct {
	nets    []*net.IPNet
	expires time.Time
}

func newUserspaceDialLookupCache() *userspaceDialLookupCache {
	return &userspaceDialLookupCache{
		routes:   make(map[string]userspaceCachedRoute),
		prefixes: make(map[string]userspaceCachedPrefixes),
	}
}

// userspaceDialLookupCacheLimit bounds the cache; past it, it starts over.
const userspaceDialLookupCacheLimit = 4096

func (c *userspaceDialLookupCache) routeIface(ip net.IP) string {
	key := ip.String()
	now := time.Now()
	c.mu.Lock()
	if item, ok := c.routes[key]; ok && now.Before(item.expires) {
		c.mu.Unlock()
		return item.iface
	}
	c.mu.Unlock()
	iface := userspaceRouteIfaceLookup(ip)
	c.mu.Lock()
	if len(c.routes) >= userspaceDialLookupCacheLimit {
		c.routes = make(map[string]userspaceCachedRoute)
	}
	c.routes[key] = userspaceCachedRoute{iface: iface, expires: now.Add(userspaceDialLookupTTL)}
	c.mu.Unlock()
	return iface
}

func (c *userspaceDialLookupCache) ifacePrefixes(name string) []*net.IPNet {
	now := time.Now()
	c.mu.Lock()
	if item, ok := c.prefixes[name]; ok && now.Before(item.expires) {
		c.mu.Unlock()
		return item.nets
	}
	c.mu.Unlock()
	nets := userspaceIfacePrefixLookup(name)
	c.mu.Lock()
	if len(c.prefixes) >= userspaceDialLookupCacheLimit {
		c.prefixes = make(map[string]userspaceCachedPrefixes)
	}
	c.prefixes[name] = userspaceCachedPrefixes{nets: nets, expires: now.Add(userspaceDialLookupTTL)}
	c.mu.Unlock()
	return nets
}

// lookupUserspaceIfacePrefixes returns the networks of the addresses on the
// named interface.
func lookupUserspaceIfacePrefixes(name string) []*net.IPNet {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return nil
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return nil
	}
	nets := make([]*net.IPNet, 0, len(addrs))
	for _, addr := range addrs {
		if ipNet, ok := addr.(*net.IPNet); ok && ipNet != nil {
			nets = append(nets, &net.IPNet{IP: ipNet.IP.Mask(ipNet.Mask), Mask: ipNet.Mask})
		}
	}
	return nets
}
