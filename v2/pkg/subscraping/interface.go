package subscraping

import (
	"context"

	"github.com/projectdiscovery/subfinder/v2/pkg/core"
	"github.com/projectdiscovery/subfinder/v2/pkg/session"
)

// Source is an interface inherited by each passive source
type Source interface {

	// Name returns the name of the source. It is preferred to use lower case names.
	Name() string

	// Daemon creates a daemon goroutine for sources
	Daemon(ctx context.Context, e *session.Extractor, input <-chan string, output chan<- core.Task)

	// IsDefault returns true if the current source should be
	// used as part of the default execution.
	IsDefault() bool

	// MissingKeys checks if source requires keys and are available
	MissingKeys() bool

	// HasRecursiveSupport returns true if the current source
	// accepts subdomains (e.g. subdomain.domain.tld),
	// not just root domains.
	HasRecursiveSupport() bool

	// NeedsKey returns true if the source requires an API key
	NeedsKey() bool

	// AddKeys adds given keys to source
	AddKeys(key ...string)
}
