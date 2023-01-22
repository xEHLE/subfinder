// Package anubis logic
package anubis

import (
	"context"
	"fmt"
	"net/http"

	jsoniter "github.com/json-iterator/go"
	"github.com/projectdiscovery/subfinder/v2/pkg/core"
	"github.com/projectdiscovery/subfinder/v2/pkg/session"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

// Source is the passive scraping agent
type Source struct {
	subscraping.BaseSource
}

// Source Daemon
func (s *Source) Daemon(ctx context.Context, e *session.Extractor, input <-chan string, output chan<- core.Task) {
	s.init()
	s.BaseSource.Daemon(ctx, e, input, output)
}

// inits the source before passing to daemon
func (s *Source) init() {
	s.BaseSource.SourceName = "anubis"
	s.BaseSource.RequiresKey = false
	s.BaseSource.Default = true
	s.BaseSource.Recursive = false
	s.BaseSource.CreateTask = s.dispatcher
}

func (s *Source) dispatcher(domain string) core.Task {
	task := core.Task{}
	task.RequestOpts = &session.RequestOpts{
		Method: http.MethodGet, URL: fmt.Sprintf("https://jonlu.ca/anubis/subdomains/%s", domain),
		Source: "anubis",
	}

	task.OnResponse = func(t *core.Task, resp *http.Response, e *core.Executor) error {
		defer resp.Body.Close()
		var subdomains []string
		err := jsoniter.NewDecoder(resp.Body).Decode(&subdomains)
		if err != nil {
			return err
		}
		for _, record := range subdomains {
			e.Result <- core.Result{Source: s.Name(), Type: core.Subdomain, Value: record}
		}
		return nil
	}
	return task
}
