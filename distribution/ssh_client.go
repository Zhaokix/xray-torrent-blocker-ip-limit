package distribution

import (
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"

	"xray-ip-limit/config"
)

type Runner interface {
	Run(ctx context.Context, target config.RemoteTarget, command string) error
}

type SSHRunner struct{}

func (SSHRunner) Run(ctx context.Context, target config.RemoteTarget, command string) error {
	remote := target.User + "@" + target.Host
	args := []string{
		"-p", strconv.Itoa(target.Port),
		"-o", "BatchMode=yes",
		"-o", "StrictHostKeyChecking=yes",
		remote,
		command,
	}

	cmd := exec.CommandContext(ctx, "ssh", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("ssh command failed: %w: %s", err, string(output))
	}
	return nil
}

type ConfiguredSSHRunner struct {
	cfg config.RemoteEnforcement
}

func (r ConfiguredSSHRunner) Run(ctx context.Context, target config.RemoteTarget, command string) error {
	args := buildConfiguredSSHArgs(r.cfg, target, command)
	cmd := exec.CommandContext(ctx, "ssh", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("ssh command failed: %w: %s", err, string(output))
	}
	return nil
}

func buildConfiguredSSHArgs(cfg config.RemoteEnforcement, target config.RemoteTarget, command string) []string {
	remote := target.User + "@" + target.Host
	args := []string{
		"-p", strconv.Itoa(target.Port),
		"-o", "BatchMode=yes",
		"-o", "StrictHostKeyChecking=yes",
	}
	if strings.TrimSpace(cfg.SSHConfigPath) != "" {
		args = append(args, "-F", cfg.SSHConfigPath)
	}
	if strings.TrimSpace(cfg.SSHKeyPath) != "" {
		args = append(args, "-i", cfg.SSHKeyPath)
	}
	if strings.TrimSpace(cfg.KnownHostsPath) != "" && strings.TrimSpace(cfg.SSHConfigPath) == "" {
		args = append(args, "-o", "UserKnownHostsFile="+cfg.KnownHostsPath)
	}
	args = append(args, remote, command)
	return args
}
