package iplimit

import (
	"sync"
	"time"
)

type Decision struct {
	Exceeded   bool
	UniqueIPs  int
	BanningIP  string
	Identifier string
}

type Detector struct {
	limit   int
	window  time.Duration
	mu      sync.Mutex
	windows map[string]map[string]time.Time
}

func New(limit int, window time.Duration) *Detector {
	return &Detector{
		limit:   limit,
		window:  window,
		windows: make(map[string]map[string]time.Time),
	}
}

func (d *Detector) Observe(identifier, ip string, now time.Time) Decision {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.windows[identifier] == nil {
		d.windows[identifier] = make(map[string]time.Time)
	}

	d.windows[identifier][ip] = now
	d.cleanupLocked(now)

	uniqueIPs := len(d.windows[identifier])
	if uniqueIPs <= d.limit {
		return Decision{
			Exceeded:   false,
			UniqueIPs:  uniqueIPs,
			Identifier: identifier,
		}
	}

	delete(d.windows[identifier], ip)

	return Decision{
		Exceeded:   true,
		UniqueIPs:  uniqueIPs,
		BanningIP:  ip,
		Identifier: identifier,
	}
}

func (d *Detector) Cleanup(now time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.cleanupLocked(now)
}

func (d *Detector) ActiveCount(identifier string) int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.windows[identifier])
}

func (d *Detector) HasActiveIP(identifier, ip string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	_, exists := d.windows[identifier][ip]
	return exists
}

func (d *Detector) cleanupLocked(now time.Time) {
	for identifier, ips := range d.windows {
		for ip, lastSeen := range ips {
			if now.Sub(lastSeen) > d.window {
				delete(ips, ip)
			}
		}
		if len(ips) == 0 {
			delete(d.windows, identifier)
		}
	}
}
