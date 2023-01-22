// Package hackertarget logic
package hackertarget

import (
	"bufio"
	"context"
	"fmt"
	"net/http"

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
	s.BaseSource.SourceName = "hackertarget"
	s.BaseSource.Recursive = true
	s.BaseSource.Default = true
	s.BaseSource.RequiresKey = false
	s.BaseSource.CreateTask = s.dispatcher
}

func (s *Source) dispatcher(domain string) core.Task {
	task := core.Task{
		Domain: domain,
	}

	task.RequestOpts = &session.RequestOpts{
		Method: http.MethodGet,
		URL:    fmt.Sprintf("http://api.hackertarget.com/hostsearch/?q=%s", domain),
		Source: "hackertarget",
	}

	task.OnResponse = func(t *core.Task, resp *http.Response, executor *core.Executor) error {
		defer resp.Body.Close()
		scanner := bufio.NewScanner(resp.Body)
		for scanner.Scan() {
			line := scanner.Text()
			if line == "" {
				continue
			}
			match := executor.Extractor.Get(domain).FindAllString(line, -1)
			for _, subdomain := range match {
				executor.Result <- core.Result{Source: s.Name(), Type: core.Subdomain, Value: subdomain}
			}
		}
		return nil
	}
	return task
}
