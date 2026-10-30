package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Mode of operation.
type Mode string

const (
	ModeDevelopment Mode = "development"
	ModeProduction  Mode = "production"
)

// Config is validated at boot (OPS-001). Unknown keys fail via KnownFields.
type Config struct {
	Mode   Mode         `yaml:"mode" json:"mode"`
	Server ServerConfig `yaml:"server" json:"server"`
	Keys   KeysConfig   `yaml:"keys" json:"keys"`
	Identity IdentityConfig `yaml:"identity" json:"identity"`
	Agents AgentsConfig `yaml:"agents" json:"agents"`
	AIAssist AIAssistConfig `yaml:"ai_assist" json:"ai_assist"`
	Network NetworkConfig `yaml:"network" json:"network"`
	Storage StorageConfig `yaml:"storage" json:"storage"`
	Retention RetentionConfig `yaml:"retention" json:"retention"`
	Labels LabelsConfig `yaml:"labels" json:"labels"`
	Portal PortalConfig `yaml:"portal" json:"portal"`
}

type ServerConfig struct {
	Internal      ListenerConfig `yaml:"internal" json:"internal"`
	Portal        PortalListener `yaml:"portal" json:"portal"`
	Metrics       MetricsConfig  `yaml:"metrics" json:"metrics"`
	PublicBaseURL string         `yaml:"public_base_url" json:"public_base_url"`
}

type ListenerConfig struct {
	Listen            string    `yaml:"listen" json:"listen"`
	RequireClientCert bool      `yaml:"require_client_cert" json:"require_client_cert"`
	TLS               TLSConfig `yaml:"tls" json:"tls"`
}

type PortalListener struct {
	Enabled        bool     `yaml:"enabled" json:"enabled"`
	Listen         string   `yaml:"listen" json:"listen"`
	TrustedProxies []string `yaml:"trusted_proxies" json:"trusted_proxies"`
	TLS            TLSConfig `yaml:"tls" json:"tls"`
}

type MetricsConfig struct {
	Listen string `yaml:"listen" json:"listen"`
}

type TLSConfig struct {
	CertFile string `yaml:"cert_file" json:"cert_file"`
	KeyFile  string `yaml:"key_file" json:"key_file"`
}

type KeysConfig struct {
	MasterKeyFile string `yaml:"master_key_file" json:"master_key_file"`
}

type IdentityConfig struct {
	OIDC            OIDCConfig    `yaml:"oidc" json:"oidc"`
	Session         SessionConfig `yaml:"session" json:"session"`
	AllowDevHeaders bool          `yaml:"allow_dev_headers" json:"allow_dev_headers"`
}

type OIDCConfig struct {
	Issuer           string            `yaml:"issuer" json:"issuer"`
	ClientID         string            `yaml:"client_id" json:"client_id"`
	ClientSecretFile string            `yaml:"client_secret_file" json:"client_secret_file"`
	RequireAMR       []string          `yaml:"require_amr" json:"require_amr"`
	GroupRoleMap     map[string]string `yaml:"group_role_map" json:"group_role_map"`
}

type SessionConfig struct {
	IdleMinutes    int `yaml:"idle_minutes" json:"idle_minutes"`
	AbsoluteHours  int `yaml:"absolute_hours" json:"absolute_hours"`
}

type AgentsConfig struct {
	MCP   MCPConfig   `yaml:"mcp" json:"mcp"`
	OAuth OAuthConfig `yaml:"oauth" json:"oauth"`
}

type MCPConfig struct {
	Enabled        bool   `yaml:"enabled" json:"enabled"`
	Protocol       string `yaml:"protocol" json:"protocol"`
	Compat20251125 bool   `yaml:"compat_2025_11_25" json:"compat_2025_11_25"`
}

type OAuthConfig struct {
	DCR                     bool   `yaml:"dcr" json:"dcr"`
	AccessTokenTTL          string `yaml:"access_token_ttl" json:"access_token_ttl"`
	RequireSenderConstraint bool   `yaml:"require_sender_constraint" json:"require_sender_constraint"`
}

type AIAssistConfig struct {
	Enabled bool `yaml:"enabled" json:"enabled"`
}

type NetworkConfig struct {
	Egress  string   `yaml:"egress" json:"egress"` // none | allowlist
	Allow   []string `yaml:"allow" json:"allow"`
}

type StorageConfig struct {
	DataDir   string `yaml:"data_dir" json:"data_dir"`
	BackupDir string `yaml:"backup_dir" json:"backup_dir"`
}

type RetentionConfig struct {
	AILogsDays             int `yaml:"ai_logs_days" json:"ai_logs_days"`
	AuditYears             int `yaml:"audit_years" json:"audit_years"`
	EvidenceYearsAfterEnd  int `yaml:"evidence_years_after_end" json:"evidence_years_after_end"`
}

type LabelsConfig struct {
	Markings map[string]string `yaml:"markings" json:"markings"`
}

type PortalConfig struct {
	Enabled bool `yaml:"enabled" json:"enabled"`
}

// Default returns a development-safe baseline (not production-ready until TLS paths set).
func Default() Config {
	return Config{
		Mode: ModeDevelopment,
		Server: ServerConfig{
			Internal: ListenerConfig{Listen: "127.0.0.1:8443"},
			Portal:   PortalListener{Enabled: false, Listen: "127.0.0.1:9443"},
			Metrics:  MetricsConfig{Listen: "127.0.0.1:9090"},
			PublicBaseURL: "https://127.0.0.1:8443",
		},
		Keys: KeysConfig{},
		Identity: IdentityConfig{
			Session: SessionConfig{IdleMinutes: 30, AbsoluteHours: 12},
		},
		Agents: AgentsConfig{
			MCP:   MCPConfig{Enabled: true, Protocol: "2026-07-28"},
			OAuth: OAuthConfig{AccessTokenTTL: "10m", RequireSenderConstraint: true},
		},
		AIAssist: AIAssistConfig{Enabled: false},
		Network:  NetworkConfig{Egress: "none"},
		Storage:  StorageConfig{DataDir: "./data", BackupDir: "./backup"},
		Retention: RetentionConfig{AILogsDays: 90, AuditYears: 7, EvidenceYearsAfterEnd: 7},
		Labels: LabelsConfig{Markings: map[string]string{
			"Privileged": "Privileged & Confidential — Prepared at the Direction of Counsel",
		}},
	}
}

// Load reads and validates a YAML config file.
func Load(path string) (Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	cfg := Default()
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		return Config{}, fmt.Errorf("config parse: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// Validate enforces OPS-001 production refusals.
func (c Config) Validate() error {
	if c.Mode != ModeDevelopment && c.Mode != ModeProduction {
		return fmt.Errorf("invalid mode %q", c.Mode)
	}
	if c.Storage.DataDir == "" {
		return errors.New("storage.data_dir required")
	}
	if c.Mode == ModeProduction {
		if c.Server.Internal.TLS.CertFile == "" || c.Server.Internal.TLS.KeyFile == "" {
			return errors.New("production mode requires TLS cert and key")
		}
		if c.Keys.MasterKeyFile == "" {
			return errors.New("production mode requires keys.master_key_file")
		}
		if c.Server.Portal.Enabled && len(c.Server.Portal.TrustedProxies) == 0 {
			return errors.New("portal enabled in production requires trusted_proxies")
		}
		if c.Identity.AllowDevHeaders {
			return errors.New("production mode refuses identity.allow_dev_headers")
		}
	}
	return nil
}

// RefuseSecretEnv fails if known secret names appear in the environment (OPS-002).
func RefuseSecretEnv() error {
	banned := []string{
		"OPENTPRM_MASTER_KEY",
		"OPENTPRM_OIDC_SECRET",
		"OPENTPRM_TLS_KEY",
		"MASTER_KEY",
		"OIDC_CLIENT_SECRET",
	}
	for _, name := range banned {
		if os.Getenv(name) != "" {
			return fmt.Errorf("secret %s must not be set in environment (OPS-002)", name)
		}
	}
	return nil
}

// JSONSchema returns a minimal JSON Schema document for docs/CI.
func JSONSchema() json.RawMessage {
	return json.RawMessage(`{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "opentprm/config/v1",
  "type": "object",
  "additionalProperties": false,
  "required": ["mode", "server", "storage"],
  "properties": {
    "mode": {"enum": ["development", "production"]},
    "server": {"type": "object"},
    "keys": {"type": "object"},
    "identity": {"type": "object"},
    "agents": {"type": "object"},
    "ai_assist": {"type": "object"},
    "network": {"type": "object"},
    "storage": {"type": "object"},
    "retention": {"type": "object"},
    "labels": {"type": "object"},
    "portal": {"type": "object"}
  }
}`)
}
