package subscraping

import (
	"context"
	"math/rand"
	"strings"
	"sync"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/roundrobin"
	"github.com/projectdiscovery/subfinder/v2/pkg/core"
	"github.com/projectdiscovery/subfinder/v2/pkg/session"
)

// MultipleKeyPartsLength defines multipart length
const MultipleKeyPartsLength = 2

// BaseSource is type that is embedded/inherited by all sources
type BaseSource struct {
	SourceName  string                        // Source Name
	RequiresKey bool                          // Requires keys
	Default     bool                          // Default specifies if source is default
	Recursive   bool                          // Recursive specifies if sources supports recursive enum
	Keys        []string                      // Stores api keys
	CreateTask  func(domain string) core.Task // creates and returns tasks taking for given
	// internal wg
	wg sync.WaitGroup
	rb *roundrobin.RoundRobin
}

// Source Daemon or background process
func (s *BaseSource) Daemon(ctx context.Context, e *session.Extractor, input <-chan string, output chan<- core.Task) {
	ctxcancel, cancel := context.WithCancel(ctx)
	defer cancel()

	if s.MissingKeys() {
		// keys missing
		gologger.Debug().Label(s.SourceName).Msgf("missing api keys. skipping..")
		return
	}
	for {
		select {
		case <-ctxcancel.Done():
			gologger.Debug().Msgf("closing %v\n", s.SourceName)
			close(output)
			return
		case domain, ok := <-input:
			if !ok {
				s.wg.Wait()
				gologger.Debug().Msgf("closing %v\n", s.SourceName)
				close(output)
				return
			}
			task := s.CreateTask(domain)
			task.RequestOpts.Cancel = cancel // Option to cancel source under certain conditions (ex: ratelimit)
			if task.HasSubtasks {
				s.wg.Add(1)
				task.Cleanup = func() {
					s.wg.Done()
				}
			}
			if task.RequestOpts != nil {
				output <- task
			}
		}
	}
}

// Name returns name of source
func (s *BaseSource) Name() string {
	return s.SourceName
}

// IsDefault returns true if source is default
func (s *BaseSource) IsDefault() bool {
	return s.Default
}

// HasRecursiveSupport returns true if source has recursive support
func (s *BaseSource) HasRecursiveSupport() bool {
	return s.Recursive
}

// NeedsKey returns true if source requires key
func (s *BaseSource) NeedsKey() bool {
	return s.RequiresKey
}

// MissingKeys checks if keys are missing
func (s *BaseSource) MissingKeys() bool {
	return s.RequiresKey && len(s.Keys) == 0
}

// AddKeys adds apikeys to source
func (s *BaseSource) AddKeys(key ...string) {
	if s.Keys == nil {
		s.Keys = []string{}
	}
	s.Keys = append(s.Keys, key...)
	if len(s.Keys) != 0 {
		s.rb, _ = roundrobin.New(s.Keys...)
	}
}

// GetKey returns a random key
func (s *BaseSource) GetNextKey() string {
	length := len(s.Keys)
	if length == 0 {
		return ""
	}
	if s.rb != nil {
		return s.rb.Next().String()
	}
	return s.Keys[rand.Intn(length)]
}

// GetMultiPartKey returns multiple parts of single key
func GetMultiPartKey(key string) (partA, partB string, ok bool) {
	parts := strings.Split(key, ":")
	ok = (len(parts) == MultipleKeyPartsLength)
	if ok {
		partA = parts[0]
		partB = parts[1]
	}
	return
}
