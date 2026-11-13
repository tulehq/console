package app

import (
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/gasmod/gas"
	"github.com/gasmod/gas/config"

	"tule.dev/console/internal/web"
)

// hstsSettings configures the Strict-Transport-Security header. It is only
// sent when MaxAge is set, so plain-HTTP deployments can leave it out.
type hstsSettings struct {
	MaxAge time.Duration
}

// ConsoleSettings are the console's own settings: the base URL of each
// service it shows, empty for a service it does not, the region it signs
// for, how long a session lasts, whether the session cookie is marked
// Secure whatever the connection, how many sessions the console and each
// key may hold, and the proxies whose X-Forwarded-For it trusts.
type ConsoleSettings struct {
	FunctionsEndpoint   string
	ObjectStoreEndpoint string
	AccountsEndpoint    string
	IdentityEndpoint    string
	MailboxEndpoint     string
	QueuesEndpoint      string
	TrustedProxies      string
	SecretStoreEndpoint string
	Region              string
	trusted             []netip.Prefix
	MaxSessions         int
	MaxSessionsPerKey   int
	SessionTTL          time.Duration
	SecureCookie        bool
}

// Trusted returns the trusted proxies, parsed.
func (s *ConsoleSettings) Trusted() []netip.Prefix {
	return s.trusted
}

// endpoints returns each endpoint setting with its name, in the order the
// console lists the services.
func (s *ConsoleSettings) endpoints() []struct {
	value *string
	name  string
} {
	return []struct {
		value *string
		name  string
	}{
		{&s.ObjectStoreEndpoint, "ObjectStoreEndpoint"},
		{&s.SecretStoreEndpoint, "SecretStoreEndpoint"},
		{&s.AccountsEndpoint, "AccountsEndpoint"},
		{&s.IdentityEndpoint, "IdentityEndpoint"},
		{&s.MailboxEndpoint, "MailboxEndpoint"},
		{&s.QueuesEndpoint, "QueuesEndpoint"},
		{&s.FunctionsEndpoint, "FunctionsEndpoint"},
	}
}

// errNoEndpoint is returned when no service is configured: there would be
// nothing to show and no service to verify a key against.
var errNoEndpoint = errors.New("config: set at least one TULE_Console_*Endpoint; " +
	"the console shows the services it is pointed at")

// Config is the bound application configuration. It keeps the store it was
// bound from, which the app registers as the gas.ConfigProvider so services
// can read settings Config itself does not model.
type Config struct {
	HSTS    *hstsSettings
	Console *ConsoleSettings `validate:"required"`

	store gas.ConfigProvider
	Env   config.Environment
}

const (
	envVarSeparator = "_"
	envVarPrefix    = "TULE_"
)

// LoadConfig loads configuration from a .env file and then the process
// environment, the later source winning.
func LoadConfig() (*Config, error) {
	return LoadConfigFrom(
		config.NewDotEnvProvider(
			config.WithDotEnvSeparator(envVarSeparator),
			config.WithDotEnvFileNotFoundPanic(false),
		),
		config.NewEnvProvider(
			config.WithEnvSeparator(envVarSeparator),
			config.WithEnvPrefix(envVarPrefix),
		),
	)
}

// LoadConfigFrom loads configuration from the given providers in order, then
// applies the same defaults and binding as LoadConfig. Tests use it to inject
// a provider of their own.
func LoadConfigFrom(provs ...config.Provider) (*Config, error) {
	env := config.NewEnvExtension()

	opts := make([]config.Option, 0, len(provs)+1)
	opts = append(opts, config.WithExtension(env))

	for _, p := range provs {
		opts = append(opts, config.WithProvider(p))
	}

	store := config.New(opts...)

	if err := store.Load(); err != nil {
		return nil, fmt.Errorf("config: load: %w", err)
	}

	return bindConfig(store, env.Current())
}

func bindConfig(store gas.ConfigProvider, env config.Environment) (*Config, error) {
	if err := applyDefaults(store); err != nil {
		return nil, err
	}

	cfg := Config{Env: env, store: store}
	if err := store.Bind(&cfg); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	if err := checkConsole(cfg.Console); err != nil {
		return nil, err
	}

	return &cfg, nil
}

// checkConsole holds every endpoint that is set to an absolute http or https
// URL, without its trailing slash, and requires at least one, a region and
// a positive session lifetime.
func checkConsole(s *ConsoleSettings) error {
	if s == nil {
		return errNoEndpoint
	}
	configured := 0
	for _, e := range s.endpoints() {
		if *e.value == "" {
			continue
		}
		if err := checkEndpoint(e.name, *e.value); err != nil {
			return err
		}
		*e.value = strings.TrimRight(*e.value, "/")
		configured++
	}
	if configured == 0 {
		return errNoEndpoint
	}
	if s.Region == "" {
		return errors.New("config: Console.Region must not be empty")
	}
	if s.SessionTTL <= 0 {
		return errors.New("config: Console.SessionTTL must be positive")
	}
	return checkSignIns(s)
}

// checkSignIns requires room for a session and reads the trusted proxies.
func checkSignIns(s *ConsoleSettings) error {
	if s.MaxSessions < 1 || s.MaxSessionsPerKey < 1 {
		return errors.New(
			"config: Console.MaxSessions and Console.MaxSessionsPerKey must be at least 1",
		)
	}
	trusted, err := web.ParsePrefixes(s.TrustedProxies)
	if err != nil {
		return fmt.Errorf("config: Console.TrustedProxies: %w", err)
	}
	s.trusted = trusted
	return nil
}

// checkEndpoint holds the endpoint setting name to an absolute http or
// https URL with no query or fragment.
func checkEndpoint(name, value string) error {
	u, err := url.Parse(value)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" ||
		u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("config: Console.%s %q is not an http or https URL", name, value)
	}
	return nil
}

func applyDefaults(store gas.ConfigProvider) error {
	var errs []error
	setDefault := func(key string, value any) {
		if err := store.SetDefault(key, value); err != nil {
			errs = append(errs, fmt.Errorf("config: default %s: %w", key, err))
		}
	}

	// 9070, after the 9000 to 9060 of object-store, secret-store, accounts,
	// identity, mailbox, queues and functions, so they can all run at once.
	setDefault("Server.Port", 9070)

	// Uploads and downloads stream through the console, so a request or a
	// response may be as large as an object. Five minutes covers a 1 GiB
	// object at about 30 Mbit/s, far below what a local or container
	// network carries. IdleTimeout matches the gas default, set here so it
	// is visible rather than inherited.
	setDefault("Server.ReadTimeout", "5m")
	setDefault("Server.WriteTimeout", "5m")
	setDefault("Server.IdleTimeout", "120s")

	// The headers get 30s, well inside the whole request's budget. gas
	// requires ReadHeaderTimeout to be positive.
	setDefault("Server.ReadHeaderTimeout", "30s")

	// As the other services: within the 10s docker stop gives, and above
	// the 6.5s net/http may take to close a connection that never sent a
	// request.
	setDefault("Server.ShutdownTimeout", "7s")

	for _, key := range []string{
		"Console.ObjectStoreEndpoint", "Console.SecretStoreEndpoint",
		"Console.AccountsEndpoint", "Console.IdentityEndpoint",
		"Console.MailboxEndpoint", "Console.QueuesEndpoint",
		"Console.FunctionsEndpoint",
	} {
		setDefault(key, "")
	}
	setDefault("Console.Region", "us-east-1")
	setDefault("Console.SessionTTL", "12h")
	setDefault("Console.SecureCookie", false)
	setDefault("Console.MaxSessions", 10000)
	setDefault("Console.MaxSessionsPerKey", 10)
	setDefault("Console.TrustedProxies", "")

	return errors.Join(errs...)
}
