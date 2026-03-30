package distribution

import (
	"context"
	"fmt"
	"os/exec"
	"strconv"

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
