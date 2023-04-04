// Package chaos logic
package chaos

import (
	"context"
	"fmt"

	"github.com/projectdiscovery/chaos-client/pkg/chaos"
	"github.com/projectdiscovery/subfinder/v2/pkg/core"
	"github.com/projectdiscovery/subfinder/v2/pkg/session"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

// Source is the passive scraping agent
type Source struct {
	subscraping.BaseSource
}

// inits the source before passing to daemon
func (s *Source) Init() {
	s.BaseSource.SourceName = "chaos"
	s.BaseSource.Recursive = false
	s.BaseSource.Default = true
	s.BaseSource.RequiresKey = true
	s.BaseSource.CreateTask = s.dispatcher
}

func (s *Source) dispatcher(domain string) core.Task {
	task := core.Task{
		Domain: domain,
		RequestOpts: &session.RequestOpts{
			Source: "chaos",
		},
	}

	// should not reference any variables/methods outside of task
	task.Override = func(t *core.Task, ctx context.Context, executor *core.Executor) error {
		randomApiKey := s.BaseSource.GetNextKey()

		chaosClient := chaos.New(randomApiKey)
		for result := range chaosClient.GetSubdomains(&chaos.SubdomainsRequest{
			Domain: t.Domain,
		}) {
			if result.Error != nil {
				executor.Result <- core.Result{Input: domain, Source: t.RequestOpts.Source, Type: core.Error, Error: result.Error}
				break
			}
			executor.Result <- core.Result{Input: domain,
				Source: t.RequestOpts.Source, Type: core.Subdomain, Value: fmt.Sprintf("%s.%s", result.Subdomain, domain),
			}
		}
		return nil // does not fallback to default task execution
	}
	return task
}
