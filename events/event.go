package events

import "time"

type Reason string

const (
	ReasonIPLimit Reason = "ip_limit"
	ReasonTorrent Reason = "torrent"
)

type Action string

const (
	ActionBan   Action = "ban"
	ActionUnban Action = "unban"
)

type Event struct {
	Reason            Reason
	Action            Action
	RawUsername       string
	ProcessedUsername string
	ClientIP          string
	Source            string
	DetectedAt        time.Time
	EnforcedAt        time.Time
	BanDuration       time.Duration
	ExpiresAt         time.Time
}

func NewIPLimitBanEvent(rawUsername, processedUsername, clientIP, source string, detectedAt time.Time, banDuration time.Duration) Event {
	return Event{
		Reason:            ReasonIPLimit,
		Action:            ActionBan,
		RawUsername:       rawUsername,
		ProcessedUsername: processedUsername,
		ClientIP:          clientIP,
		Source:            source,
		DetectedAt:        detectedAt,
		BanDuration:       banDuration,
		ExpiresAt:         detectedAt.Add(banDuration),
	}
}

func NewTorrentBanEvent(rawUsername, processedUsername, clientIP, source string, detectedAt time.Time, banDuration time.Duration) Event {
	return Event{
		Reason:            ReasonTorrent,
		Action:            ActionBan,
		RawUsername:       rawUsername,
		ProcessedUsername: processedUsername,
		ClientIP:          clientIP,
		Source:            source,
		DetectedAt:        detectedAt,
		BanDuration:       banDuration,
		ExpiresAt:         detectedAt.Add(banDuration),
	}
}

func NewIPLimitUnbanEvent(rawUsername, processedUsername, clientIP, source string, detectedAt time.Time) Event {
	return Event{
		Reason:            ReasonIPLimit,
		Action:            ActionUnban,
		RawUsername:       rawUsername,
		ProcessedUsername: processedUsername,
		ClientIP:          clientIP,
		Source:            source,
		DetectedAt:        detectedAt,
		BanDuration:       0,
		ExpiresAt:         detectedAt,
	}
}

func NewTorrentUnbanEvent(rawUsername, processedUsername, clientIP, source string, detectedAt time.Time) Event {
	return Event{
		Reason:            ReasonTorrent,
		Action:            ActionUnban,
		RawUsername:       rawUsername,
		ProcessedUsername: processedUsername,
		ClientIP:          clientIP,
		Source:            source,
		DetectedAt:        detectedAt,
		BanDuration:       0,
		ExpiresAt:         detectedAt,
	}
}
