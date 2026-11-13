// Command tule-console serves a web console for the Tule services: it
// browses each configured service and runs the everyday actions on it,
// through the service's own API, signed with the key of the signed-in
// session.
package main

import (
	"context"
	"fmt"
	"log"

	"tule.dev/console/internal/app"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() (err error) {
	cfg, cfgErr := app.LoadConfig()
	if cfgErr != nil {
		return fmt.Errorf("failed to load config: %w", cfgErr)
	}

	a, appErr := app.New(cfg)
	if appErr != nil {
		return fmt.Errorf("failed to create application: %w", appErr)
	}

	if runErr := a.Run(context.Background()); runErr != nil {
		return fmt.Errorf("app exited with error: %w", runErr)
	}

	return
}
