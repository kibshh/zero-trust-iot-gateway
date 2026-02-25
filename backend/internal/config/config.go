package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

const (
	EnvServerHost            = "ZTG_SERVER_HOST"
	EnvServerPort            = "ZTG_SERVER_PORT"
	EnvServerReadTimeoutSec  = "ZTG_SERVER_READ_TIMEOUT_SEC"
	EnvServerWriteTimeoutSec = "ZTG_SERVER_WRITE_TIMEOUT_SEC"
	EnvServerIdleTimeoutSec  = "ZTG_SERVER_IDLE_TIMEOUT_SEC"
	EnvSigningKeyPath        = "ZTG_SIGNING_KEY_PATH"
	EnvDatabaseDSN           = "ZTG_DATABASE_DSN"
	EnvTLSEnabled            = "ZTG_TLS_ENABLED"
	EnvTLSCertFile           = "ZTG_TLS_CERT_FILE"
	EnvTLSKeyFile            = "ZTG_TLS_KEY_FILE"
	EnvTLSClientCAFile       = "ZTG_TLS_CLIENT_CA_FILE"
	EnvTLSRequireClientCert  = "ZTG_TLS_REQUIRE_CLIENT_CERT"
	EnvTLSMinVersion         = "ZTG_TLS_MIN_VERSION"

	MinPortNumber = 1
	MaxPortNumber = 65535
	TLSVersion12  = "1.2"
	TLSVersion13  = "1.3"
)

// TLSConfig holds TLS settings.
type TLSConfig struct {
	Enabled           bool
	CertFile          string
	KeyFile           string
	ClientCAFile      string
	RequireClientCert bool
	MinVersion        string
}

// Config holds backend runtime configuration loaded from environment variables.
type Config struct {
	ServerHost            string
	ServerPort            int
	ServerReadTimeoutSec  int
	ServerWriteTimeoutSec int
	ServerIdleTimeoutSec  int
	SigningKeyPath        string
	DatabaseDSN           string
	TLS                   TLSConfig
}

// LoadFromEnv loads and validates configuration from environment variables.
func LoadFromEnv() (Config, error) {
	cfg := Config{
		ServerHost:            envOrDefault(EnvServerHost, "0.0.0.0"),
		ServerPort:            intEnvOrDefault(EnvServerPort, 8080),
		ServerReadTimeoutSec:  intEnvOrDefault(EnvServerReadTimeoutSec, 15),
		ServerWriteTimeoutSec: intEnvOrDefault(EnvServerWriteTimeoutSec, 15),
		ServerIdleTimeoutSec:  intEnvOrDefault(EnvServerIdleTimeoutSec, 60),
		SigningKeyPath:        strings.TrimSpace(os.Getenv(EnvSigningKeyPath)),
		DatabaseDSN:           strings.TrimSpace(os.Getenv(EnvDatabaseDSN)),
		TLS: TLSConfig{
			Enabled:           boolEnvOrDefault(EnvTLSEnabled, false),
			CertFile:          strings.TrimSpace(os.Getenv(EnvTLSCertFile)),
			KeyFile:           strings.TrimSpace(os.Getenv(EnvTLSKeyFile)),
			ClientCAFile:      strings.TrimSpace(os.Getenv(EnvTLSClientCAFile)),
			RequireClientCert: boolEnvOrDefault(EnvTLSRequireClientCert, false),
			MinVersion:        envOrDefault(EnvTLSMinVersion, TLSVersion12),
		},
	}

	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}

	return cfg, nil
}

// Validate checks that the configuration is coherent.
func (c Config) Validate() error {
	if c.ServerHost == "" {
		return fmt.Errorf("invalid %s: must not be empty", EnvServerHost)
	}
	if c.ServerPort < MinPortNumber || c.ServerPort > MaxPortNumber {
		return fmt.Errorf("invalid %s: must be in range %d..%d", EnvServerPort, MinPortNumber, MaxPortNumber)
	}
	if c.ServerReadTimeoutSec <= 0 {
		return fmt.Errorf("invalid %s: must be > 0", EnvServerReadTimeoutSec)
	}
	if c.ServerWriteTimeoutSec <= 0 {
		return fmt.Errorf("invalid %s: must be > 0", EnvServerWriteTimeoutSec)
	}
	if c.ServerIdleTimeoutSec <= 0 {
		return fmt.Errorf("invalid %s: must be > 0", EnvServerIdleTimeoutSec)
	}
	if c.SigningKeyPath == "" {
		return fmt.Errorf("invalid %s: must not be empty", EnvSigningKeyPath)
	}
	if c.DatabaseDSN == "" {
		return fmt.Errorf("invalid %s: must not be empty", EnvDatabaseDSN)
	}
	if c.TLS.Enabled {
		if c.TLS.MinVersion != TLSVersion12 && c.TLS.MinVersion != TLSVersion13 {
			return fmt.Errorf("invalid %s: must be %q or %q", EnvTLSMinVersion, TLSVersion12, TLSVersion13)
		}
		if c.TLS.CertFile == "" {
			return fmt.Errorf("invalid %s: required when TLS is enabled", EnvTLSCertFile)
		}
		if c.TLS.KeyFile == "" {
			return fmt.Errorf("invalid %s: required when TLS is enabled", EnvTLSKeyFile)
		}
		if c.TLS.RequireClientCert && c.TLS.ClientCAFile == "" {
			return fmt.Errorf("invalid %s: required when mutual TLS is enabled", EnvTLSClientCAFile)
		}
	}
	return nil
}

func envOrDefault(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

func intEnvOrDefault(key string, fallback int) int {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return fallback
	}
	return n
}

func boolEnvOrDefault(key string, fallback bool) bool {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return fallback
	}
	return b
}
