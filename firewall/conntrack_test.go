package firewall

import (
	"errors"
	"strings"
	"testing"
)

func TestConntrackDelPrefersNetlinkWhenAvailable(t *testing.T) {
	originalNetlink := conntrackDeleteViaNetlink
	originalShell := conntrackDeleteViaShell
	defer func() {
		conntrackDeleteViaNetlink = originalNetlink
		conntrackDeleteViaShell = originalShell
	}()

	netlinkCalled := false
	shellCalled := false
	conntrackDeleteViaNetlink = func(ip string) error {
		netlinkCalled = true
		if ip != "203.0.113.10" {
			t.Fatalf("unexpected ip %q", ip)
		}
		return nil
	}
	conntrackDeleteViaShell = func(string) error {
		shellCalled = true
		return nil
	}

	if err := conntrackDel("203.0.113.10"); err != nil {
		t.Fatalf("conntrackDel returned error: %v", err)
	}
	if !netlinkCalled {
		t.Fatal("expected netlink deleter to be called")
	}
	if shellCalled {
		t.Fatal("did not expect shell fallback when netlink succeeds")
	}
}

func TestConntrackDelFallsBackToShell(t *testing.T) {
	originalNetlink := conntrackDeleteViaNetlink
	originalShell := conntrackDeleteViaShell
	defer func() {
		conntrackDeleteViaNetlink = originalNetlink
		conntrackDeleteViaShell = originalShell
	}()

	conntrackDeleteViaNetlink = func(string) error {
		return errors.New("netlink unavailable")
	}
	shellCalled := false
	conntrackDeleteViaShell = func(ip string) error {
		shellCalled = true
		if ip != "203.0.113.11" {
			t.Fatalf("unexpected ip %q", ip)
		}
		return nil
	}

	if err := conntrackDel("203.0.113.11"); err != nil {
		t.Fatalf("conntrackDel returned error: %v", err)
	}
	if !shellCalled {
		t.Fatal("expected shell fallback to be called")
	}
}

func TestConntrackDelReturnsCombinedError(t *testing.T) {
	originalNetlink := conntrackDeleteViaNetlink
	originalShell := conntrackDeleteViaShell
	defer func() {
		conntrackDeleteViaNetlink = originalNetlink
		conntrackDeleteViaShell = originalShell
	}()

	conntrackDeleteViaNetlink = func(string) error {
		return errors.New("netlink unavailable")
	}
	conntrackDeleteViaShell = func(string) error {
		return errors.New("conntrack CLI failed")
	}

	err := conntrackDel("203.0.113.12")
	if err == nil {
		t.Fatal("expected conntrackDel to return error")
	}
	for _, fragment := range []string{"netlink unavailable", "conntrack CLI failed"} {
		if !strings.Contains(err.Error(), fragment) {
			t.Fatalf("expected error to contain %q, got %v", fragment, err)
		}
	}
}
