package torrent

import "strings"

type Decision struct {
	Matched    bool
	BanningIP  string
	Identifier string
	Tag        string
}

type Detector struct {
	tag string
}

func New(tag string) *Detector {
	return &Detector{tag: strings.TrimSpace(tag)}
}

func (d *Detector) Observe(line, identifier, ip string) Decision {
	if d.tag == "" || identifier == "" || ip == "" {
		return Decision{}
	}
	if !strings.Contains(line, d.tag) {
		return Decision{}
	}

	return Decision{
		Matched:    true,
		BanningIP:  ip,
		Identifier: identifier,
		Tag:        d.tag,
	}
}
