// Package shodan logic
package shodan

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

type dnsdbLookupResponse struct {
	Domain     string   `json:"domain"`
	Subdomains []string `json:"subdomains"`
	Result     int      `json:"result"`
	Error      string   `json:"error"`
}

// Source Daemon
func (s *Source) Daemon(ctx context.Context, e *session.Extractor, input <-chan string, output chan<- core.Task) {
	s.init()
	s.BaseSource.Daemon(ctx, e, input, output)
}

// inits the source before passing to daemon
func (s *Source) init() {
	s.BaseSource.SourceName = "shodan"
	s.BaseSource.Default = true
	s.BaseSource.Recursive = false
	s.BaseSource.RequiresKey = true
	s.BaseSource.CreateTask = s.dispatcher
}

func (s *Source) dispatcher(domain string) core.Task {
	task := core.Task{
		Domain: domain,
	}
	randomApiKey := s.GetRandomKey()
	searchURL := fmt.Sprintf("https://api.shodan.io/dns/domain/%s?key=%s", domain, randomApiKey)
	task.RequestOpts = &session.RequestOpts{
		Method: http.MethodGet,
		URL:    searchURL,
		Source: "shodan",
		UID:    randomApiKey,
	}

	task.OnResponse = func(t *core.Task, resp *http.Response, executor *core.Executor) error {
		defer resp.Body.Close()
		var response dnsdbLookupResponse
		err := jsoniter.NewDecoder(resp.Body).Decode(&response)
		if err != nil {
			return err
		}

		if response.Error != "" {
			return fmt.Errorf("%v", response.Error)
		}

		for _, data := range response.Subdomains {
			executor.Result <- core.Result{
				Source: s.Name(), Type: core.Subdomain, Value: fmt.Sprintf("%s.%s", data, domain),
			}
		}
		return nil
	}
	return task
}
