// Package bevigil logic
package bevigil

import (
	"context"
	"fmt"
	"net/http"

	jsoniter "github.com/json-iterator/go"
	"github.com/projectdiscovery/subfinder/v2/pkg/core"
	"github.com/projectdiscovery/subfinder/v2/pkg/session"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

type Response struct {
	Domain     string   `json:"domain"`
	Subdomains []string `json:"subdomains"`
}

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
	s.BaseSource.SourceName = "bevigil"
	s.BaseSource.RequiresKey = true
	s.BaseSource.Default = true
	s.BaseSource.Recursive = false
	s.BaseSource.CreateTask = s.dispatcher
}

func (s *Source) dispatcher(domain string) core.Task {
	task := core.Task{}
	randomApiKey := s.BaseSource.GetRandomKey()
	getUrl := fmt.Sprintf("https://osint.bevigil.com/api/%s/subdomains/", domain)

	task.RequestOpts = &session.RequestOpts{
		Method: http.MethodGet,
		URL:    getUrl,
		Headers: map[string]string{
			"X-Access-Token": randomApiKey, "User-Agent": "subfinder",
		},
		Source: "bevigil",
		UID:    randomApiKey,
	}

	task.OnResponse = func(t *core.Task, resp *http.Response, executor *core.Executor) error {
		defer resp.Body.Close()
		var subdomains []string
		var response Response
		err := jsoniter.NewDecoder(resp.Body).Decode(&response)
		if err != nil {
			return err
		}
		if len(response.Subdomains) > 0 {
			subdomains = response.Subdomains
		}
		for _, subdomain := range subdomains {
			executor.Result <- core.Result{Source: "bevigil", Type: core.Subdomain, Value: subdomain}
		}
		return nil
	}
	return task
}
