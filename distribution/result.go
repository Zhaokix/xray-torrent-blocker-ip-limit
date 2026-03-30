package distribution

import (
	"time"

	"xray-ip-limit/events"
)

type Scope string

const (
	ScopeLocalOnly      Scope = "local_only"
	ScopeRemoteOnly     Scope = "remote_only"
	ScopeLocalAndRemote Scope = "local_and_remote"
)

type TargetResult struct {
	TargetName string
	Host       string
	Action     events.Action
	Success    bool
	ErrorKind  string
	ErrorText  string
	StartedAt  time.Time
	FinishedAt time.Time
}

type Result struct {
	Scope           Scope
	Reason          events.Reason
	ClientIP        string
	LocalAttempted  bool
	LocalApplied    bool
	LocalError      string
	TargetResults   []TargetResult
	FullySuccessful bool
	PartiallyFailed bool
}

func (r Result) AnyApplied() bool {
	if r.LocalApplied {
		return true
	}
	for _, target := range r.TargetResults {
		if target.Success {
			return true
		}
	}
	return false
}
