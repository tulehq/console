// Package app loads the configuration and wires the services, modules and
// middleware into a gas application.
package app

import (
	"fmt"
	"net/http"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/gasmod/gas"
	templatefs "github.com/gasmod/gas/template/fs"
	"github.com/gasmod/gas/ui"

	"tule.dev/console/internal/awsclient"
	"tule.dev/console/internal/httpx"
	"tule.dev/console/internal/modules/accounts"
	"tule.dev/console/internal/modules/functions"
	"tule.dev/console/internal/modules/health"
	"tule.dev/console/internal/modules/iam"
	"tule.dev/console/internal/modules/mail"
	"tule.dev/console/internal/modules/objects"
	"tule.dev/console/internal/modules/queues"
	"tule.dev/console/internal/modules/secrets"
	"tule.dev/console/internal/modules/signin"
	"tule.dev/console/internal/session"
	"tule.dev/console/internal/web"
)

// pageCSP is the policy of every console page: scripts, styles, frames and
// fetches from the console itself only, nothing inline, and no page of the
// console in anyone's frame. The mail preview, the one frame, answers with
// its own policy.
const pageCSP = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; " +
	"frame-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'none'; object-src 'none'"

// Sign-in is limited to signInBurst failed attempts per client address,
// refilled one every signInRefill; a successful sign-in does not count.
const (
	signInBurst  = 10
	signInRefill = 6 * time.Second
)

// Overrides replace what the app would build from the configuration, for
// tests: the key verifier and the client of each section. A nil field is
// built from the configuration.
type Overrides struct {
	Verifier    signin.Verifier
	ObjectStore objects.NewClient
	SecretStore secrets.NewClient
	Accounts    accounts.NewClient
	IAM         iam.NewClient
	Mailbox     mail.NewAPI
	Queues      queues.NewClients
	Functions   functions.NewClients
	// Store, when set, is given the session store once it is made.
	Store func(*session.Store)
	// Limiter, when set, is given the sign-in limiter once it is made.
	Limiter func(*web.Limiter)
}

// New builds the application from cfg. extra options are applied after the
// app's own.
func New(cfg *Config, extra ...gas.Option) (*gas.App, error) {
	return NewWith(cfg, Overrides{}, extra...)
}

// NewWith builds the application from cfg with o's overrides.
func NewWith(cfg *Config, o Overrides, extra ...gas.Option) (*gas.App, error) {
	logger, lErr := newLogger(cfg.Env)
	if lErr != nil {
		return nil, lErr
	}

	store, limiter, err := newSignIns(cfg.Console, o)
	if err != nil {
		return nil, err
	}

	opts := append([]gas.Option{gas.WithErrorHandler(web.ErrorHandler)}, extra...)
	app := gas.NewApp(opts...)

	httpClient := awsclient.NewHTTPClient()
	sections := sectionsOf(cfg.Console, httpClient)

	verify := o.Verifier
	if verify == nil {
		if verify, err = signin.NewVerifier(verifierEndpoints(sections)); err != nil {
			return nil, err
		}
	}

	app.RegisterServiceInstance[gas.ConfigProvider](cfg.store)
	app.RegisterServiceInstance[gas.Logger](logger)
	app.RegisterScopedService[httpx.RequestLogger](resolveRequestLogger)
	app.RegisterServiceInstance[*session.Store](store)

	app.RegisterSingletonService[gas.TemplateProvider](templatefs.NewStore(web.Templates()))
	app.RegisterSingletonService[ui.Provider](ui.New[gas.TemplateProvider](
		ui.WithStaticFS(web.Static()),
		ui.WithFuncs(web.Funcs()),
	))
	app.RegisterSingletonService[*web.Renderer](func(p ui.Provider) *web.Renderer {
		return web.NewRenderer(p, sections)
	})

	app.RegisterServiceInstance[signin.Deps](
		signin.Deps{Store: store, Verify: verify, Limiter: limiter},
	)
	app.RegisterSingletonService[*signin.Module](signin.NewModule)
	app.RegisterSingletonService[*health.Module](health.NewModule)
	registerSections(app, sections, o)

	installMiddleware(app.Router(), cfg, logger, store)

	return app, nil
}

// newSignIns returns the session store and the sign-in limiter of s, and
// gives them to o's hooks.
func newSignIns(s *ConsoleSettings, o Overrides) (*session.Store, *web.Limiter, error) {
	store, err := session.NewStore(s.SessionTTL, s.SecureCookie, session.Limits{
		Max:    s.MaxSessions,
		PerKey: s.MaxSessionsPerKey,
	})
	if err != nil {
		return nil, nil, err
	}
	if o.Store != nil {
		o.Store(store)
	}
	limiter := web.NewLimiter(signInBurst, signInRefill, web.DefaultLimiterSize, s.Trusted())
	if o.Limiter != nil {
		o.Limiter(limiter)
	}
	return store, limiter, nil
}

// sectionsOf returns a section for each configured endpoint, in the order
// the console lists them.
func sectionsOf(s *ConsoleSettings, client *http.Client) []web.Section {
	all := []struct {
		url, key, title, path string
	}{
		{s.ObjectStoreEndpoint, objects.Key, "Object store", objects.Path},
		{s.SecretStoreEndpoint, secrets.Key, "Secret store", secrets.Path},
		{s.AccountsEndpoint, accounts.Key, "Accounts", accounts.Path},
		{s.IdentityEndpoint, iam.Key, "Identity", iam.Path},
		{s.MailboxEndpoint, mail.Key, "Mailbox", mail.Path},
		{s.QueuesEndpoint, queues.Key, "Queues", queues.Path},
		{s.FunctionsEndpoint, functions.Key, "Functions", functions.Path},
	}
	var out []web.Section
	for _, a := range all {
		if a.url == "" {
			continue
		}
		out = append(out, web.Section{
			Key: a.key, Title: a.title, Path: a.path,
			Endpoint: awsclient.Endpoint{URL: a.url, Region: s.Region, HTTP: client},
		})
	}
	return out
}

func verifierEndpoints(sections []web.Section) signin.Endpoints {
	var e signin.Endpoints
	for _, s := range sections {
		ep := s.Endpoint
		switch s.Key {
		case iam.Key:
			e.Identity = &ep
		case objects.Key:
			e.ObjectStore = &ep
		case secrets.Key:
			e.SecretStore = &ep
		case accounts.Key:
			e.Accounts = &ep
		case mail.Key:
			e.Mailbox = &ep
		case queues.Key:
			e.Queues = &ep
		case functions.Key:
			e.Functions = &ep
		}
	}
	return e
}

// registerSections registers the module of each configured section with
// its client, the real one over the section's endpoint unless o replaces
// it.
//
//nolint:gocognit,cyclop,funlen // one registration per section
func registerSections(app *gas.App, sections []web.Section, o Overrides) {
	for _, s := range sections {
		ep := s.Endpoint
		switch s.Key {
		case objects.Key:
			fn := o.ObjectStore
			if fn == nil {
				fn = func(c aws.Credentials) objects.API { return awsclient.S3(ep, c) }
			}
			app.RegisterServiceInstance[objects.NewClient](fn)
			app.RegisterSingletonService[*objects.Module](objects.NewModule)
		case secrets.Key:
			fn := o.SecretStore
			if fn == nil {
				fn = func(c aws.Credentials) secrets.API { return awsclient.SecretsManager(ep, c) }
			}
			app.RegisterServiceInstance[secrets.NewClient](fn)
			app.RegisterSingletonService[*secrets.Module](secrets.NewModule)
		case accounts.Key:
			fn := o.Accounts
			if fn == nil {
				fn = func(c aws.Credentials) accounts.API { return awsclient.Organizations(ep, c) }
			}
			app.RegisterServiceInstance[accounts.NewClient](fn)
			app.RegisterSingletonService[*accounts.Module](accounts.NewModule)
		case iam.Key:
			fn := o.IAM
			if fn == nil {
				fn = func(c aws.Credentials) iam.API { return awsclient.IAM(ep, c) }
			}
			app.RegisterServiceInstance[iam.NewClient](fn)
			app.RegisterSingletonService[*iam.Module](iam.NewModule)
		case mail.Key:
			fn := o.Mailbox
			if fn == nil {
				fn = func(c aws.Credentials) mail.API { return mail.NewClient(ep, c) }
			}
			app.RegisterServiceInstance[mail.NewAPI](fn)
			app.RegisterSingletonService[*mail.Module](mail.NewModule)
		case queues.Key:
			fn := o.Queues
			if fn == nil {
				fn = func(c aws.Credentials) queues.Clients {
					return queues.Clients{
						Inspect: queues.NewInspection(ep, c),
						SQS:     awsclient.SQS(ep, c),
					}
				}
			}
			app.RegisterServiceInstance[queues.NewClients](fn)
			app.RegisterSingletonService[*queues.Module](queues.NewModule)
		case functions.Key:
			fn := o.Functions
			if fn == nil {
				fn = func(c aws.Credentials) functions.Clients {
					return functions.Clients{
						Lambda:  awsclient.Lambda(ep, c),
						History: functions.NewRetrieval(ep, c),
					}
				}
			}
			app.RegisterServiceInstance[functions.NewClients](fn)
			app.RegisterSingletonService[*functions.Module](functions.NewModule)
		}
	}
}

func installMiddleware(r *gas.Router, cfg *Config, logger gas.Logger, store *session.Store) {
	r.UseMiddlewareFunc(nil, httpx.RequestID(cfg.Env))

	// X-Forwarded-For is read only by the sign-in limiter, and only from
	// the peers TULE_Console_TrustedProxies names (web.ClientIP); without
	// them, sign-ins are limited per peer address. The logs keep the peer
	// address either way, since the header is the client's to choose.

	r.UseMiddlewareFunc(nil, withRequestLogger(logger))

	r.UseMiddlewareFunc(nil, gas.RequestLogger[httpx.RequestLogger]())

	var hsts string
	if cfg.HSTS != nil && cfg.HSTS.MaxAge > 0 {
		hsts = fmt.Sprintf("max-age=%0.f", cfg.HSTS.MaxAge.Seconds())
	}
	r.UseMiddlewareFunc(nil, gas.SecurityHeaders(
		gas.WithSecurityHeadersStrictTransportSecurity(hsts),
		gas.WithSecurityHeadersContentSecurityPolicy(pageCSP),
		gas.WithSecurityHeadersReferrerPolicy("same-origin"),
		gas.WithSecurityHeadersCrossOriginOpenerPolicy("same-origin"),
		gas.WithSecurityHeadersCrossOriginResourcePolicy("same-origin"),
	))

	r.UseMiddlewareFunc(nil, web.Guard(store))

	r.NotFound(nil, web.NotFound)
}
