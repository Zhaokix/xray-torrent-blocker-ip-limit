package extractors

import (
	"net"
	"net/netip"
	"strings"
)

type AccessLogEntry struct {
	ClientIP string
	Username string
}

// ParseXrayAccessLogLine extracts the client IP and username from an Xray access log line.
// It expects a "from " token followed by host:port and returns false when required fields are missing.
func ParseXrayAccessLogLine(line string) (AccessLogEntry, bool) {
	fromIdx := strings.Index(line, "from ")
	if fromIdx == -1 {
		return AccessLogEntry{}, false
	}

	ipStart := fromIdx + len("from ")
	if ipStart >= len(line) {
		return AccessLogEntry{}, false
	}

	addrToken, ok := extractAddressToken(line[ipStart:])
	if !ok {
		return AccessLogEntry{}, false
	}

	clientIP, ok := parseClientIP(addrToken)
	if !ok {
		return AccessLogEntry{}, false
	}

	emailIdx := strings.Index(line, "email: ")
	if emailIdx == -1 {
		return AccessLogEntry{ClientIP: clientIP}, true
	}

	emailStart := emailIdx + len("email: ")
	if emailStart >= len(line) {
		return AccessLogEntry{ClientIP: clientIP}, true
	}

	emailFields := strings.Fields(line[emailStart:])
	if len(emailFields) == 0 {
		return AccessLogEntry{ClientIP: clientIP}, true
	}

	return AccessLogEntry{
		ClientIP: clientIP,
		Username: emailFields[0],
	}, true
}

func extractAddressToken(value string) (string, bool) {
	fields := strings.Fields(value)
	if len(fields) == 0 {
		return "", false
	}

	token := fields[0]
	switch {
	case strings.HasPrefix(token, "tcp:"):
		return strings.TrimPrefix(token, "tcp:"), true
	case strings.HasPrefix(token, "udp:"):
		return strings.TrimPrefix(token, "udp:"), true
	default:
		return token, true
	}
}

func parseClientIP(token string) (string, bool) {
	if strings.HasSuffix(token, ":") {
		return "", false
	}

	host, _, err := net.SplitHostPort(token)
	if err != nil {
		addr, parseErr := netip.ParseAddr(token)
		if parseErr != nil {
			return "", false
		}
		return addr.Unmap().String(), true
	}

	addr, err := netip.ParseAddr(host)
	if err != nil {
		return "", false
	}

	return addr.Unmap().String(), true
}
