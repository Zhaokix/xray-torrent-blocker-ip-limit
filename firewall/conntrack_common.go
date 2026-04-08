package firewall

import (
	"fmt"
	"os/exec"
	"strings"
)

var (
	conntrackDeleteViaNetlink = deleteConntrackViaNetlink
	conntrackDeleteViaShell   = deleteConntrackViaShell
)

func conntrackDel(ip string) error {
	netlinkErr := conntrackDeleteViaNetlink(ip)
	if netlinkErr == nil {
		return nil
	}

	shellErr := conntrackDeleteViaShell(ip)
	if shellErr == nil {
		return nil
	}

	return fmt.Errorf("netlink: %v; shell: %v", netlinkErr, shellErr)
}

func deleteConntrackViaShell(ip string) error {
	var errs []string
	for _, direction := range []string{"-s", "-d"} {
		cmd := exec.Command("conntrack", "-D", direction, ip)
		output, err := cmd.CombinedOutput()
		if err != nil {
			text := strings.TrimSpace(string(output))
			if text != "" && strings.Contains(text, "0 flow entries have been deleted") {
				continue
			}
			if text == "" {
				text = err.Error()
			}
			errs = append(errs, fmt.Sprintf("%s: %s", direction, text))
		}
	}
	if len(errs) == 0 {
		return nil
	}
	return fmt.Errorf(strings.Join(errs, "; "))
}
