package app

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/gasmod/gas/config"
)

func load(t *testing.T, env map[string]string) (*Config, error) {
	t.Helper()
	t.Setenv("TULE_GasEnv", "testing")
	for k, v := range env {
		t.Setenv(k, v)
	}
	return LoadConfigFrom(
		config.NewEnvProvider(config.WithEnvSeparator("_"), config.WithEnvPrefix("TULE_")),
	)
}

func TestDefaults(t *testing.T) {
	cfg, err := load(
		t,
		map[string]string{"TULE_Console_ObjectStoreEndpoint": "http://localhost:9000/"},
	)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	c := cfg.Console
	if c.ObjectStoreEndpoint != "http://localhost:9000" {
		t.Fatalf("endpoint %q, want the trailing slash trimmed", c.ObjectStoreEndpoint)
	}
	if c.Region != "us-east-1" || c.SessionTTL != 12*time.Hour || c.SecureCookie ||
		c.QueuesEndpoint != "" {
		t.Fatalf("defaults %+v", c)
	}
	if port := cfg.store.Get("Server.Port"); fmt.Sprint(port) != "9070" {
		t.Fatalf("Server.Port %v, want 9070", port)
	}
}

func TestSettings(t *testing.T) {
	cfg, err := load(t, map[string]string{
		"TULE_Console_IdentityEndpoint": "https://identity.internal:9030",
		"TULE_Console_Region":           "eu-west-1",
		"TULE_Console_SessionTTL":       "30m",
		"TULE_Console_SecureCookie":     "true",
	})
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	c := cfg.Console
	if c.IdentityEndpoint != "https://identity.internal:9030" || c.Region != "eu-west-1" ||
		c.SessionTTL != 30*time.Minute || !c.SecureCookie {
		t.Fatalf("settings %+v", c)
	}
}

func TestInvalid(t *testing.T) {
	for name, env := range map[string]map[string]string{
		"no endpoint":     {},
		"not a URL":       {"TULE_Console_MailboxEndpoint": "localhost:9040"},
		"another scheme":  {"TULE_Console_MailboxEndpoint": "ftp://localhost:9040"},
		"a query":         {"TULE_Console_MailboxEndpoint": "http://localhost:9040?x=1"},
		"zero TTL":        {"TULE_Console_MailboxEndpoint": "http://localhost:9040", "TULE_Console_SessionTTL": "0s"},
		"an empty region": {"TULE_Console_MailboxEndpoint": "http://localhost:9040", "TULE_Console_Region": ""},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := load(t, env); err == nil {
				t.Fatal("the configuration was accepted")
			} else if strings.Contains(err.Error(), "SecretAccessKey") {
				t.Fatalf("error %v", err)
			}
		})
	}
}

func TestSessionAndProxySettings(t *testing.T) {
	cfg, err := load(
		t,
		map[string]string{"TULE_Console_ObjectStoreEndpoint": "http://localhost:9000"},
	)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	c := cfg.Console
	if c.MaxSessions != 10000 || c.MaxSessionsPerKey != 10 || len(c.Trusted()) != 0 {
		t.Fatalf("defaults %+v, trusted %v", c, c.Trusted())
	}

	cfg, err = load(t, map[string]string{
		"TULE_Console_ObjectStoreEndpoint": "http://localhost:9000",
		"TULE_Console_TrustedProxies":      "10.0.0.0/8, 192.168.1.5, fd00::/8",
		"TULE_Console_MaxSessions":         "50",
		"TULE_Console_MaxSessionsPerKey":   "3",
	})
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	c = cfg.Console
	if got := fmt.Sprint(c.Trusted()); got != "[10.0.0.0/8 192.168.1.5/32 fd00::/8]" {
		t.Fatalf("trusted %s", got)
	}
	if c.MaxSessions != 50 || c.MaxSessionsPerKey != 3 {
		t.Fatalf("caps %+v", c)
	}
}

func TestInvalidSessionAndProxySettings(t *testing.T) {
	for name, env := range map[string]map[string]string{
		"a junk proxy":    {"TULE_Console_TrustedProxies": "10.0.0.0/8, proxy.internal"},
		"no sessions":     {"TULE_Console_MaxSessions": "0"},
		"no key sessions": {"TULE_Console_MaxSessionsPerKey": "0"},
	} {
		env["TULE_Console_ObjectStoreEndpoint"] = "http://localhost:9000"
		t.Run(name, func(t *testing.T) {
			if _, err := load(t, env); err == nil {
				t.Fatal("the configuration was accepted")
			}
		})
	}
}
