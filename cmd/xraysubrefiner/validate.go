package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
)

var uuidV4 = regexp.MustCompile(`^[0-9a-fA-F\-]{16,}$`)

func validateLines(lines []string, key string) error {
	var problems []string
	for idx, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		if err := validateLine(line); err != nil {
			problems = append(problems, fmt.Sprintf("  [%d] %s -> %v", idx, line, err))
		}
	}
	if len(problems) == 0 {
		return nil
	}
	return fmt.Errorf("validation failed for key %q (%d bad lines):\n%s",
		key, len(problems), strings.Join(problems, "\n"))
}

func validateLine(line string) error {
	switch {
	case strings.HasPrefix(line, "vmess://"):
		return validateVmess(line)
	case strings.HasPrefix(line, "vless://"):
		return validateVless(line)
	case strings.HasPrefix(line, "trojan://"):
		return validateTrojan(line)
	case strings.HasPrefix(line, "ss://"):
		return validateShadowsocks(line)
	default:
		return fmt.Errorf("unsupported or unexpected scheme")
	}
}

func filterValidLines(lines []string, key string) []string {
    var out []string

    for idx, raw := range lines {
        line := strings.TrimSpace(raw)
        if line == "" {
            continue
        }

        if err := validateLine(line); err != nil {
            fmt.Fprintf(os.Stderr, "!! %s: skip invalid line [%d]: %v\n", key, idx, err)
            continue
        }

        out = append(out, line)
    }

    return out
}

func validateVmess(line string) error {
    raw := strings.TrimPrefix(line, "vmess://")

    if i := strings.IndexByte(raw, '#'); i >= 0 {
        raw = raw[:i]
    }
    raw = strings.TrimSpace(raw)
    if raw == "" {
        return errors.New("vmess: empty payload after trimming fragment")
    }

    payload, err := decodeVmessBase64(raw)
    if err != nil {
        return fmt.Errorf("vmess base64 decode: %w", err)
    }

    var m map[string]any
    if err := json.Unmarshal(payload, &m); err != nil {
        return fmt.Errorf("vmess json: %w", err)
    }

    host, _ := m["add"].(string)
    if strings.TrimSpace(host) == "" {
        return errors.New("vmess: missing add (server)")
    }

    port, err := extractPortFromJSON(m["port"])
    if err != nil {
        return fmt.Errorf("vmess: %w", err)
    }
    if port <= 0 || port > 99999 {
        return fmt.Errorf("vmess: invalid port %d", port)
    }

    id, _ := m["id"].(string)
    if strings.TrimSpace(id) == "" {
        return errors.New("vmess: missing id (UUID)")
    }

    return nil
}

func decodeVmessBase64(b64 string) ([]byte, error) {
	b64 = strings.TrimSpace(b64)
	if b64 == "" {
		return nil, errors.New("empty vmess payload")
	}
	b64 = strings.ReplaceAll(b64, "-", "+")
	b64 = strings.ReplaceAll(b64, "_", "/")
	if m := len(b64) % 4; m != 0 {
		b64 += strings.Repeat("=", 4-m)
	}
	data, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func extractPortFromJSON(v any) (int, error) {
	switch val := v.(type) {
	case string:
		if val == "" {
			return 0, errors.New("empty port")
		}
		p, err := strconv.Atoi(val)
		if err != nil {
			return 0, fmt.Errorf("cannot parse port %q", val)
		}
		return p, nil
	case float64:
		return int(val), nil
	case int:
		return val, nil
	default:
		return 0, errors.New("port missing or wrong type")
	}
}

func validateVless(line string) error {
    u, err := url.Parse(line)
    if err != nil {
        return fmt.Errorf("parse: %w", err)
    }

    if u.Hostname() == "" {
        return errors.New("missing host")
    }

    port, err := parsePort(u.Port())
    if err != nil {
        return err
    }
    if port <= 0 || port > 65535 {
        return fmt.Errorf("invalid port %d", port)
    }

    user := ""
    if u.User != nil {
        user = u.User.Username()
    }
    if strings.TrimSpace(user) == "" {
        return errors.New("missing user/id in vless url")
    }

    return nil
}

func validateTrojan(line string) error {
	u, err := url.Parse(line)
	if err != nil {
		return fmt.Errorf("parse: %w", err)
	}
	if u.Hostname() == "" {
		return errors.New("missing host")
	}
	port, err := parsePort(u.Port())
	if err != nil {
		return err
	}
	if port <= 0 || port > 65535 {
		return fmt.Errorf("invalid port %d", port)
	}
	pass := ""
	if u.User != nil {
		pass = u.User.Username()
	}
	if strings.TrimSpace(pass) == "" {
		return errors.New("missing trojan password in user part")
	}
	return nil
}

func validateShadowsocks(line string) error {
	u, err := url.Parse(line)
	if err != nil {
		return fmt.Errorf("parse: %w", err)
	}
	if u.Hostname() == "" {
		return errors.New("missing host")
	}
	port, err := parsePort(u.Port())
	if err != nil {
		return err
	}
	if port <= 0 || port > 65535 {
		return fmt.Errorf("invalid port %d", port)
	}

	user := ""
	if u.User != nil {
		user = u.User.Username()
	}
	if strings.TrimSpace(user) == "" {
		return errors.New("missing userinfo (method:password)")
	}

	method, err := decodeSSUserInfo(user)
	if err != nil {
		return err
	}
	if method == "" {
		return errors.New("empty encryption method")
	}
	/*if password == "" {
		return errors.New("empty password")
	}*/
	return nil
}

func decodeSSUserInfo(user string) (method string, err error) {
	if dec, decErr := base64.StdEncoding.DecodeString(user); decErr == nil {
		if parts := strings.SplitN(string(dec), ":", 2); len(parts) == 2 {
			return parts[0], nil
		}
	}
	/*if !strings.Contains(user, ":") {
		return "", "", errors.New("userinfo is neither valid base64 nor method:password")
	}*/
	parts := strings.SplitN(user, ":", 2)
	return parts[0], nil
}

func parsePort(p string) (int, error) {
	if p == "" {
		return 0, errors.New("missing port")
	}
	v, err := strconv.Atoi(p)
	if err != nil {
		return 0, fmt.Errorf("cannot parse port %q", p)
	}
	return v, nil
}
