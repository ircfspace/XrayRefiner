package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Subscription struct {
	Key string `yaml:"key"`
	URL string `yaml:"url"`
}

type LiteCfg struct {
	Strategy     string `yaml:"strategy"`
	MaxTotal     int    `yaml:"max_total"`
	PerHostLimit int    `yaml:"per_host_limit"`
	N            int    `yaml:"n"`
}

type Config struct {
	AllowedSchemes []string       `yaml:"allowed_schemes"`
	Lite           LiteCfg        `yaml:"lite"`
	Subscriptions  []Subscription `yaml:"subscriptions"`
	Locations  []Subscription `yaml:"locations"`
}

var (
	rePossibleB64 = regexp.MustCompile(`^[A-Za-z0-9+/=\r\n]+$`)
	reCommentLine = regexp.MustCompile(`^\s*(#|//|;).*$`)
)

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func main() {
	cfgPath := flag.String("config", "config.yaml", "path to config.yaml")
	outDir := flag.String("out", "export", "output directory")
	timeout := flag.Duration("timeout", 20*time.Second, "HTTP client timeout")
	flag.Parse()

	cfg, err := loadConfig(*cfgPath)
	must(err)

	client := &http.Client{Timeout: *timeout}

	allowed := make(map[string]struct{})

	if len(cfg.AllowedSchemes) == 0 {
		log.Fatal("allowed_schemes is missing or empty in config.yaml")
	}

	for _, s := range cfg.AllowedSchemes {
		s = strings.ToLower(strings.TrimSpace(s))
		if s == "" {
			log.Fatal("allowed_schemes contains an empty value in config.yaml")
		}
		allowed[s] = struct{}{}
	}

	allSubs := append(cfg.Subscriptions, cfg.Locations...)
	for _, sub := range allSubs {
		fmt.Printf("Processing %s (%s)\n", sub.Key, sub.URL)
		raw, err := fetch(client, sub.URL)
		if err != nil {
			fmt.Fprintf(os.Stderr, "!! fetch error %s: %v\n", sub.URL, err)
			continue
		}

		decoded := tryDecodeIfBase64(raw)
		valid := parseAndFilterLines(decoded, allowed)

		normal := dedupe(valid)
		normal = filterValidLines(normal, sub.Key)

		fmt.Fprintf(os.Stderr, "Info: %s -> %d lines after validation\n", sub.Key, len(normal))
		if len(normal) == 0 {
			fmt.Fprintf(os.Stderr, "Info: %s has no valid configs after validation, skipping\n", sub.Key)
			continue
		}

		reachable := filterReachableLines(normal, 2*time.Second, 50)

		fmt.Fprintf(os.Stderr, "Info: %s -> %d syntactically valid, %d reachable\n",
			sub.Key, len(normal), len(reachable))

		if len(reachable) == 0 {
			fmt.Fprintf(os.Stderr, "Info: %s has no reachable endpoints, skipping exports\n", sub.Key)
			continue
		}

		lite := buildLiteTail(reachable, 100)
		ipv4, ipv6 := splitByIPVersion(reachable)

		keyDir := filepath.Join(*outDir, sub.Key)
		if err := os.MkdirAll(keyDir, 0o755); err != nil {
			must(err)
		}

		if err := writeBase64Sorted(filepath.Join(keyDir, sanitizeFileName("normal")), reachable); err != nil {
			must(err)
		}
		if err := writeBase64NoSort(filepath.Join(keyDir, sanitizeFileName("lite")), lite); err != nil {
			must(err)
		}
		if err := writeBase64Sorted(filepath.Join(keyDir, sanitizeFileName("ipv4")), ipv4); err != nil {
			must(err)
		}
		if err := writeBase64Sorted(filepath.Join(keyDir, sanitizeFileName("ipv6")), ipv6); err != nil {
			must(err)
		}

	}
}

func loadConfig(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		return nil, err
	}
	if cfg.Lite.MaxTotal <= 0 {
		cfg.Lite.MaxTotal = 100
	}
	if cfg.Lite.N <= 0 {
		cfg.Lite.N = 100
	}
	return &cfg, nil
}

func fetch(client *http.Client, rawurl string) ([]byte, error) {
	req, err := http.NewRequest("GET", rawurl, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "XraySubRefiner/1.1")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return body, nil
}

func tryDecodeIfBase64(b []byte) []byte {
	trim := bytes.TrimSpace(b)
	if len(trim) == 0 {
		return trim
	}
	if !rePossibleB64.Match(trim) {
		return b
	}
	dec, err := base64.StdEncoding.DecodeString(string(trim))
	if err != nil {
		dec2, err2 := base64.StdEncoding.DecodeString(strings.ReplaceAll(string(trim), "\n", ""))
		if err2 != nil {
			return b
		}
		dec = dec2
	}
	l := strings.ToLower(string(dec))
	if strings.Contains(l, "vless://") || strings.Contains(l, "vmess://") || strings.Contains(l, "ss://") {
		return dec
	}
	return b
}

func parseAndFilterLines(b []byte, allowed map[string]struct{}) []string {
	var out []string
	sc := bufio.NewScanner(bytes.NewReader(b))
	buf := make([]byte, 0, 1024*1024)
	sc.Buffer(buf, 10*1024*1024)

	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || reCommentLine.MatchString(line) {
			continue
		}
		items := splitPossible(line)
		for _, it := range items {
			it = strings.TrimSpace(it)
			if it == "" || reCommentLine.MatchString(it) {
				continue
			}
			l := strings.ToLower(it)
			ok := false
			for sch := range allowed {
				if strings.HasPrefix(l, sch+"://") {
					ok = true
					break
				}
			}
			if !ok {
				continue
			}
			out = append(out, normalizeScheme(it))
		}
	}
	return out
}

func normalizeScheme(s string) string {
	idx := strings.Index(s, "://")
	if idx < 0 {
		return s
	}
	return strings.ToLower(s[:idx]) + s[idx:]
}

func splitPossible(s string) []string {
	if strings.Count(s, "://") <= 1 {
		return []string{s}
	}
	parts := []string{}
	cur := s
	for {
		idx := strings.Index(cur, "://")
		if idx < 0 {
			break
		}
		start := idx - 1
		for start >= 0 && isSchemeChar(cur[start]) {
			start--
		}
		start++
		rest := cur[start:]
		next := strings.Index(rest[3:], "://")
		if next >= 0 {
			parts = append(parts, strings.TrimSpace(rest[:next+3]))
			cur = rest[next+3:]
			continue
		}
		parts = append(parts, strings.TrimSpace(rest))
		break
	}
	return parts
}

func isSchemeChar(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func dedupe(in []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		k := strings.TrimSpace(s)
		if k == "" {
			continue
		}
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, k)
	}
	return out
}

func buildLiteTail(normal []string, n int) []string {
	if n <= 0 {
		n = 100
	}
	if n > len(normal) {
		n = len(normal)
	}
	start := len(normal) - n
	return append([]string(nil), normal[start:]...)
}

func hostKey(line string) string {
	u, err := url.Parse(line)
	if err == nil && u.Host != "" {
		return strings.ToLower(u.Host)
	}
	if at := strings.Index(line, "@"); at >= 0 {
		rest := line[at+1:]
		stop := len(rest)
		if i := strings.IndexAny(rest, "?#"); i >= 0 {
			stop = i
		}
		hostport := rest[:stop]
		return strings.ToLower(hostport)
	}
	return strings.ToLower(line)
}

func writeBase64Sorted(path string, lines []string) error {
	cp := append([]string(nil), lines...)
	sort.Strings(cp)
	return writeBase64Atomic(path, cp)
}

func writeBase64NoSort(path string, lines []string) error {
	return writeBase64Atomic(path, lines)
}

func writeBase64Atomic(path string, lines []string) error {
	payload := strings.Join(lines, "\n")
	encoded := base64.StdEncoding.EncodeToString([]byte(payload))

	dir := filepath.Dir(path)
	base := filepath.Base(path)
	tmpFile, err := os.CreateTemp(dir, base+".*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmpFile.Name()

	w := bufio.NewWriter(tmpFile)
	if _, err := w.WriteString(encoded); err != nil {
		tmpFile.Close()
		_ = os.Remove(tmpPath)
		return err
	}
	if err := w.Flush(); err != nil {
		tmpFile.Close()
		_ = os.Remove(tmpPath)
		return err
	}
	if err := tmpFile.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}

	const maxRetries = 6
	for i := 0; i < maxRetries; i++ {
		_ = os.Remove(path) 
		if err := os.Rename(tmpPath, path); err != nil {
			lower := strings.ToLower(err.Error())
			busy := strings.Contains(lower, "used by another process") ||
				strings.Contains(lower, "access is denied") ||
				strings.Contains(lower, "sharing violation")
			if busy && i < maxRetries-1 {
				time.Sleep(time.Duration(200*(i+1)) * time.Millisecond)
				continue
			}
			_ = os.Remove(tmpPath)
			return fmt.Errorf("rename failed (%d tries): %w", i+1, err)
		}
		return nil
	}
	_ = os.Remove(tmpPath)
	return fmt.Errorf("rename failed after retries")
}

func sanitizeFileName(name string) string {
	name = strings.TrimSpace(name)
	name = strings.ReplaceAll(name, "/", "_")
	invalid := regexp.MustCompile(`[<>:"\\|?*\x00-\x1F]`)
	name = invalid.ReplaceAllString(name, "_")
	if name == "" {
		name = "default"
	}
	return name
}

func splitByIPVersion(lines []string) ([]string, []string) {
    var ipv4, ipv6 []string
    for _, l := range lines {
        u, err := url.Parse(l)
        if err != nil || u.Host == "" {
            continue
        }
        host := u.Host
        if strings.Contains(host, ":") {
            host = strings.Split(host, ":")[0]
        }
        if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
            ipv6 = append(ipv6, l)
            continue
        }
        if strings.Count(host, ".") == 3 {
            ipv4 = append(ipv4, l)
        } else {
            ipv6 = append(ipv6, l)
        }
    }
    return ipv4, ipv6
}
