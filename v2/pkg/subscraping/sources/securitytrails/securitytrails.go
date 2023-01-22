// Package securitytrails logic
package securitytrails

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	jsoniter "github.com/json-iterator/go"

	"github.com/projectdiscovery/subfinder/v2/pkg/core"
	"github.com/projectdiscovery/subfinder/v2/pkg/session"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

type response struct {
	Subdomains []string `json:"subdomains"`
}

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
	s.BaseSource.SourceName = "securitytrails"
	s.BaseSource.Default = true
	s.BaseSource.Recursive = true
	s.BaseSource.RequiresKey = true
	s.BaseSource.CreateTask = s.dispatcher
}

func (s *Source) dispatcher(domain string) core.Task {
	task := core.Task{
		Domain: domain,
	}
	randomApiKey := s.GetRandomKey()
	task.RequestOpts = &session.RequestOpts{
		Method:  http.MethodGet,
		URL:     fmt.Sprintf("https://api.securitytrails.com/v1/domain/%s/subdomains", domain),
		Headers: map[string]string{"APIKEY": randomApiKey},
		Source:  "securitytrails",
		UID:     randomApiKey,
	}
	task.OnResponse = func(t *core.Task, resp *http.Response, executor *core.Executor) error {
		defer resp.Body.Close()
		var securityTrailsResponse response
		err := jsoniter.NewDecoder(resp.Body).Decode(&securityTrailsResponse)
		if err != nil {
			return err
		}
		for _, subdomain := range securityTrailsResponse.Subdomains {
			if strings.HasSuffix(subdomain, ".") {
				subdomain += domain
			} else {
				subdomain = subdomain + "." + domain
			}
			executor.Result <- core.Result{Source: s.Name(), Type: core.Subdomain, Value: subdomain}
		}
		return nil
	}
	return task
}
