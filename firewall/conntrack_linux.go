//go:build linux

package firewall

import (
	"fmt"
	"net"
	"net/netip"
	"sync"

	"github.com/ti-mo/conntrack"
)

type netlinkConntrackDeleter struct {
	conn *conntrack.Conn
}

var (
	conntrackInitOnce sync.Once
	conntrackDeleter  *netlinkConntrackDeleter
	conntrackInitErr  error
)

func deleteConntrackViaNetlink(ip string) error {
	deleter, err := getNetlinkConntrackDeleter()
	if err != nil {
		return err
	}

	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return fmt.Errorf("invalid IP address %q", ip)
	}

	addr, ok := netip.AddrFromSlice(parsedIP)
	if !ok {
		return fmt.Errorf("failed to convert IP address %q", ip)
	}

	flows, err := deleter.conn.Dump(nil)
	if err != nil {
		return fmt.Errorf("dump conntrack table: %w", err)
	}

	for _, flow := range flows {
		if !flowMatchesIP(flow, addr) {
			continue
		}
		if err := deleter.conn.Delete(flow); err != nil {
			return fmt.Errorf("delete conntrack flow for %s: %w", ip, err)
		}
	}

	return nil
}

func getNetlinkConntrackDeleter() (*netlinkConntrackDeleter, error) {
	conntrackInitOnce.Do(func() {
		conn, err := conntrack.Dial(nil)
		if err != nil {
			conntrackInitErr = fmt.Errorf("connect to conntrack netlink: %w", err)
			return
		}
		conntrackDeleter = &netlinkConntrackDeleter{conn: conn}
	})

	if conntrackInitErr != nil {
		return nil, conntrackInitErr
	}
	return conntrackDeleter, nil
}

func flowMatchesIP(flow conntrack.Flow, addr netip.Addr) bool {
	return (flow.TupleOrig.IP.SourceAddress.IsValid() && flow.TupleOrig.IP.SourceAddress == addr) ||
		(flow.TupleOrig.IP.DestinationAddress.IsValid() && flow.TupleOrig.IP.DestinationAddress == addr) ||
		(flow.TupleReply.IP.SourceAddress.IsValid() && flow.TupleReply.IP.SourceAddress == addr) ||
		(flow.TupleReply.IP.DestinationAddress.IsValid() && flow.TupleReply.IP.DestinationAddress == addr)
}
