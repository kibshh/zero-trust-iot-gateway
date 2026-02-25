package config

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
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
	EnvDevEphemeralKey       = "ZTG_DEV_EPHEMERAL_KEY"

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
	DevEphemeralKey       bool
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
		DevEphemeralKey:       boolEnvOrDefault(EnvDevEphemeralKey, false),
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
	if c.DevEphemeralKey && c.SigningKeyPath != "" {
		return fmt.Errorf("invalid config: %s and %s are mutually exclusive", EnvDevEphemeralKey, EnvSigningKeyPath)
	}
	if !c.DevEphemeralKey && c.SigningKeyPath == "" {
		return fmt.Errorf("invalid %s: must not be empty (or set %s=true for dev mode)", EnvSigningKeyPath, EnvDevEphemeralKey)
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

// LoadSigningKey loads the ECDSA P-256 signing key from the path in cfg.
// If cfg.DevEphemeralKey is true, it generates an ephemeral key instead and
// logs a warning — this path must never be used in production.
func LoadSigningKey(cfg Config) (*ecdsa.PrivateKey, error) {
	if cfg.DevEphemeralKey {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("ephemeral key generation failed: %w", err)
		}
		return key, nil
	}

	data, err := os.ReadFile(cfg.SigningKeyPath)
	if err != nil {
		return nil, fmt.Errorf("reading signing key %q: %w", cfg.SigningKeyPath, err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("signing key %q: no PEM block found", cfg.SigningKeyPath)
	}

	switch block.Type {
	case "EC PRIVATE KEY":
		key, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("signing key %q: %w", cfg.SigningKeyPath, err)
		}
		if key.Curve != elliptic.P256() {
			return nil, fmt.Errorf("signing key %q: must be ECDSA P-256, got %s", cfg.SigningKeyPath, key.Curve.Params().Name)
		}
		return key, nil
	case "PRIVATE KEY":
		// PKCS#8 wrapped key
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("signing key %q: %w", cfg.SigningKeyPath, err)
		}
		key, ok := parsed.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("signing key %q: must be ECDSA P-256", cfg.SigningKeyPath)
		}
		if key.Curve != elliptic.P256() {
			return nil, fmt.Errorf("signing key %q: must be ECDSA P-256, got %s", cfg.SigningKeyPath, key.Curve.Params().Name)
		}
		return key, nil
	default:
		return nil, fmt.Errorf("signing key %q: unsupported PEM type %q", cfg.SigningKeyPath, block.Type)
	}
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
