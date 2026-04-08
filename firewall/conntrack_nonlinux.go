//go:build !linux

package firewall

import "fmt"

func deleteConntrackViaNetlink(string) error {
	return fmt.Errorf("netlink conntrack cleanup is only supported on linux")
}
