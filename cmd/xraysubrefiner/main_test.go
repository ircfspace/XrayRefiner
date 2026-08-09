package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveConfigSourcePrefersEnvValueWhenFlagUnset(t *testing.T) {
	t.Setenv(configEnvVar, "allowed_schemes:\n  - vless\n")

	got := resolveConfigSource(false, "", os.Getenv(configEnvVar))
	if got != "allowed_schemes:\n  - vless\n" {
		t.Fatalf("resolveConfigSource() = %q, want env content", got)
	}
}

func TestLoadConfigParsesRawYAMLContent(t *testing.T) {
	cfg, err := loadConfig("allowed_schemes:\n  - vless\nlite:\n  n: 12\n")
	if err != nil {
		t.Fatalf("loadConfig(raw yaml) returned error: %v", err)
	}
	if len(cfg.AllowedSchemes) != 1 || cfg.AllowedSchemes[0] != "vless" {
		t.Fatalf("unexpected allowed schemes: %#v", cfg.AllowedSchemes)
	}
	if cfg.Lite.N != 12 {
		t.Fatalf("expected lite.n to be 12, got %d", cfg.Lite.N)
	}
}

func TestLoadConfigParsesGitHubVariableStyleMultilineYAML(t *testing.T) {
	raw := "allowed_schemes:\n  - vless\nsubscriptions:\n  - key: \"location/FR\"\n    url: \"https://example.com/subscription\"\n"

	cfg, err := loadConfig(raw)
	if err != nil {
		t.Fatalf("loadConfig(multiline yaml) returned error: %v", err)
	}
	if len(cfg.Subscriptions) != 1 || cfg.Subscriptions[0].Key != "location/FR" {
		t.Fatalf("unexpected subscriptions: %#v", cfg.Subscriptions)
	}
}

func TestLoadConfigReadsFilePath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	content := []byte("allowed_schemes:\n  - vmess\nsubscriptions: []\n")
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatalf("write temp config: %v", err)
	}

	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatalf("loadConfig(file path) returned error: %v", err)
	}
	if len(cfg.AllowedSchemes) != 1 || cfg.AllowedSchemes[0] != "vmess" {
		t.Fatalf("unexpected allowed schemes: %#v", cfg.AllowedSchemes)
	}
}

func TestLoadConfigRejectsEmptySource(t *testing.T) {
	if _, err := loadConfig(""); err == nil {
		t.Fatal("loadConfig(\"\") expected an error")
	}
}
