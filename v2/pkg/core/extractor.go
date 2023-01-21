package core

import (
	"regexp"
	"sync"

	"github.com/projectdiscovery/gologger"
)

// Extracts valid subdomains from given data
type Extractor struct {
	regexes map[string]*regexp.Regexp
	mutex   sync.Mutex
}

// Get returns pointer to subdomain regex and creates one if not available
func (e *Extractor) Get(domain string) *regexp.Regexp {
	if e.regexes[domain] == nil {
		e.mutex.Lock()
		defer e.mutex.Unlock()
		var err error
		e.regexes[domain], err = regexp.Compile(`[a-zA-Z0-9\*_.-]+\.` + domain)
		if err != nil {
			gologger.Error().Msgf("failed to create regex extractor for %v", domain)
			panic(err)
		}
	}
	return e.regexes[domain]
}

func NewExtractor() *Extractor {
	return &Extractor{
		regexes: map[string]*regexp.Regexp{},
	}
}
