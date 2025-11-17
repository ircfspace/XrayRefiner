package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

func filterReachableLines(lines []string, timeout time.Duration, maxConcurrent int) []string {
    const maxToTest = 1000 

    type item struct {
        idx  int
        line string
    }

    in := make(chan item)
    var wg sync.WaitGroup

    reachable := make([]string, 0, len(lines))
    var mu sync.Mutex

    worker := func() {
        defer wg.Done()
        for it := range in {
            host, port, err := extractHostPort(it.line)
            if err != nil || host == "" || port == 0 {
                continue
            }

            addr := net.JoinHostPort(host, strconv.Itoa(port))
            conn, err := net.DialTimeout("tcp", addr, timeout)
            if err != nil {
                continue
            }
            conn.Close()

            mu.Lock()
            reachable = append(reachable, it.line)
            mu.Unlock()
        }
    }

    if maxConcurrent <= 0 {
        maxConcurrent = 20
    }
    wg.Add(maxConcurrent)
    for i := 0; i < maxConcurrent; i++ {
        go worker()
    }

    go func() {
        limit := len(lines)
        if limit > maxToTest {
            limit = maxToTest
        }

        for i := 0; i < limit; i++ {
            l := strings.TrimSpace(lines[i])
            if l == "" {
                continue
            }
            in <- item{idx: i, line: l}
        }
        close(in)
    }()

    wg.Wait()
    return reachable
}

func extractHostPort(line string) (host string, port int, err error) {
    line = strings.TrimSpace(line)
    switch {
    case strings.HasPrefix(line, "vless://"),
        strings.HasPrefix(line, "trojan://"),
        strings.HasPrefix(line, "ss://"):

        u, perr := url.Parse(line)
        if perr != nil {
            return "", 0, perr
        }
        h := u.Hostname()
        pStr := u.Port()
        if h == "" || pStr == "" {
            return "", 0, fmt.Errorf("missing host or port")
        }
        p, perr := strconv.Atoi(pStr)
        if perr != nil {
            return "", 0, perr
        }
        return h, p, nil

    case strings.HasPrefix(line, "vmess://"):
        raw := strings.TrimPrefix(line, "vmess://")
        if i := strings.IndexByte(raw, '#'); i >= 0 {
            raw = raw[:i]
        }
        raw = strings.TrimSpace(raw)
        if raw == "" {
            return "", 0, fmt.Errorf("empty vmess payload")
        }

        payload, err := decodeVmessBase64(raw)
        if err != nil {
            return "", 0, err
        }

        var m map[string]any
        if err := json.Unmarshal(payload, &m); err != nil {
            return "", 0, err
        }

        h, _ := m["add"].(string)
        if strings.TrimSpace(h) == "" {
            return "", 0, fmt.Errorf("vmess missing add")
        }
        p, err := extractPortFromJSON(m["port"])
        if err != nil {
            return "", 0, err
        }
        return h, p, nil
    }

    return "", 0, fmt.Errorf("unsupported scheme")
}