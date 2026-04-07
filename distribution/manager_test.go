package distribution

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"xray-ip-limit/config"
	"xray-ip-limit/events"
	"xray-ip-limit/firewall"
)

type fakeRunner struct {
	errByTarget map[string]error
	commands    []string
}

func (f *fakeRunner) Run(_ context.Context, target config.RemoteTarget, command string) error {
	f.commands = append(f.commands, target.Name+":"+command)
	if f.errByTarget == nil {
		return nil
	}
	return f.errByTarget[target.Name]
}

func testConfigForDistribution(t *testing.T, mode string, enabled bool) *config.Config {
	t.Helper()

	cfg := config.Default()
	cfg.DryRun = false
	cfg.RemoteEnforcement.Enabled = enabled
	cfg.RemoteEnforcement.Mode = mode
	cfg.RemoteEnforcement.ConnectTimeout = 5 * time.Second
	cfg.RemoteEnforcement.Targets = []config.RemoteTarget{
		{Name: "edge-1", Host: "198.51.100.10", Port: 22, User: "root", Backend: "iptables"},
		{Name: "edge-2", Host: "198.51.100.11", Port: 22, User: "root", Backend: "iptables"},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate returned error: %v", err)
	}
	return cfg
}

func testLocalFirewall(t *testing.T) *firewall.Manager {
	t.Helper()

	fw, err := firewall.NewManager("iptables", true)
	if err != nil {
		t.Fatalf("NewManager returned error: %v", err)
	}
	return fw
}

func TestBuildConfiguredSSHArgs(t *testing.T) {
	args := buildConfiguredSSHArgs(config.RemoteEnforcement{
		SSHConfigPath:  "/opt/iptblocker/ssh_config",
		SSHKeyPath:     "/opt/iptblocker/id_ed25519",
		KnownHostsPath: "/opt/iptblocker/known_hosts",
	}, config.RemoteTarget{
		Name: "edge-1",
		Host: "198.51.100.10",
		Port: 2222,
		User: "iptblocker",
	}, "echo test")

	joined := strings.Join(args, " ")
	for _, fragment := range []string{"-p 2222", "-F /opt/iptblocker/ssh_config", "-i /opt/iptblocker/id_ed25519", "iptblocker@198.51.100.10", "echo test"} {
		if !strings.Contains(joined, fragment) {
			t.Fatalf("expected ssh args to contain %q, got %v", fragment, args)
		}
	}
}

func TestApplyLocalOnlyUsesLocalFirewall(t *testing.T) {
	cfg := testConfigForDistribution(t, "local_only", false)
	manager := newManagerWithRunner(cfg, testLocalFirewall(t), &fakeRunner{})

	result := manager.Apply(events.NewIPLimitBanEvent("user", "user", "203.0.113.10", "log", time.Now(), time.Minute))
	if !result.LocalApplied {
		t.Fatal("expected local enforcement to be applied")
	}
	if len(result.TargetResults) != 0 {
		t.Fatalf("expected no remote target results, got %d", len(result.TargetResults))
	}
	if !result.FullySuccessful {
		t.Fatal("expected local_only result to be fully successful")
	}
}

func TestApplyRemoteOnlyUsesTargets(t *testing.T) {
	cfg := testConfigForDistribution(t, "remote_only", true)
	runner := &fakeRunner{}
	manager := newManagerWithRunner(cfg, testLocalFirewall(t), runner)

	result := manager.Apply(events.NewTorrentBanEvent("user", "user", "203.0.113.11", "log", time.Now(), time.Minute))
	if result.LocalAttempted {
		t.Fatal("did not expect local enforcement in remote_only mode")
	}
	if len(result.TargetResults) != 2 {
		t.Fatalf("expected two remote target results, got %d", len(result.TargetResults))
	}
	if !result.FullySuccessful {
		t.Fatal("expected remote_only result to be fully successful")
	}
	if len(runner.commands) != 2 {
		t.Fatalf("expected two remote commands, got %d", len(runner.commands))
	}
}

func TestApplyLocalAndRemoteReportsPartialFailure(t *testing.T) {
	cfg := testConfigForDistribution(t, "local_and_remote", true)
	runner := &fakeRunner{
		errByTarget: map[string]error{"edge-2": errors.New("ssh failed")},
	}
	manager := newManagerWithRunner(cfg, testLocalFirewall(t), runner)

	result := manager.Apply(events.NewIPLimitBanEvent("user", "user", "203.0.113.12", "log", time.Now(), time.Minute))
	if !result.LocalApplied {
		t.Fatal("expected local enforcement to succeed")
	}
	if !result.PartiallyFailed {
		t.Fatal("expected partial failure when one remote target fails")
	}
	if result.FullySuccessful {
		t.Fatal("did not expect full success when one remote target fails")
	}
}

func TestRemoteCommandSupportsSudo(t *testing.T) {
	command := remoteCommand(events.ActionBan, config.RemoteEnforcement{UseSudo: true}, config.RemoteTarget{Backend: "iptables"}, "203.0.113.12")
	if !strings.Contains(command, "sudo iptables") {
		t.Fatalf("expected sudo iptables command, got %q", command)
	}
}
