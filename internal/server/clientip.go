package server

import (
	"net"
	"net/http"
	"strings"
)

// proxies decides which peers' forwarding headers are believed.
type proxies []*net.IPNet

func (p proxies) trusted(ip net.IP) bool {
	for _, n := range p {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func peerIP(r *http.Request) net.IP {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	return net.ParseIP(host)
}

// clientIP returns the client's address. X-Forwarded-For is only read when
// the direct peer is a trusted proxy, and it is walked from the right,
// skipping trusted proxies, so a client can't spoof its address by
// prepending entries.
func (p proxies) clientIP(r *http.Request) string {
	peer := peerIP(r)
	if peer == nil {
		return r.RemoteAddr
	}
	if !p.trusted(peer) {
		return peer.String()
	}
	var hops []string
	for _, h := range r.Header.Values("X-Forwarded-For") {
		for _, part := range strings.Split(h, ",") {
			if part = strings.TrimSpace(part); part != "" {
				hops = append(hops, part)
			}
		}
	}
	for i := len(hops) - 1; i >= 0; i-- {
		ip := net.ParseIP(hops[i])
		if ip == nil {
			// An unparsable hop can't be trusted further; stop here.
			return peer.String()
		}
		if !p.trusted(ip) {
			return ip.String()
		}
	}
	return peer.String()
}

// secure reports whether the request reached us over TLS: directly, or
// through a trusted proxy that says so.
func (p proxies) secure(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	peer := peerIP(r)
	if peer == nil || !p.trusted(peer) {
		return false
	}
	proto := r.Header.Get("X-Forwarded-Proto")
	if i := strings.LastIndex(proto, ","); i >= 0 {
		proto = proto[i+1:]
	}
	return strings.EqualFold(strings.TrimSpace(proto), "https")
}
