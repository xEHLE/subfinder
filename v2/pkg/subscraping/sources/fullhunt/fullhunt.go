package fullhunt

import (
	"context"
	"fmt"
	"net/http"

	jsoniter "github.com/json-iterator/go"
	"github.com/projectdiscovery/subfinder/v2/pkg/core"
	"github.com/projectdiscovery/subfinder/v2/pkg/session"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

// fullhunt response
type fullHuntResponse struct {
	Hosts   []string `json:"hosts"`
	Message string   `json:"message"`
	Status  int      `json:"status"`
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
	s.BaseSource.SourceName = "fullhunt"
	s.BaseSource.Recursive = false
	s.BaseSource.Default = true
	s.BaseSource.RequiresKey = true
	s.BaseSource.CreateTask = s.dispatcher
}

func (s *Source) dispatcher(domain string) core.Task {
	task := core.Task{
		Domain: domain,
	}
	randomApiKey := s.BaseSource.GetRandomKey()

	task.RequestOpts = &session.RequestOpts{
		Method:  http.MethodGet,
		URL:     fmt.Sprintf("https://fullhunt.io/api/v1/domain/%s/subdomains", domain),
		Headers: map[string]string{"X-API-KEY": randomApiKey},
		Source:  "fullhunt",
		UID:     randomApiKey,
	}

	task.OnResponse = func(t *core.Task, resp *http.Response, executor *core.Executor) error {
		defer resp.Body.Close()
		var response fullHuntResponse
		err := jsoniter.NewDecoder(resp.Body).Decode(&response)
		if err != nil {
			return err
		}
		resp.Body.Close()
		for _, record := range response.Hosts {
			executor.Result <- core.Result{Source: s.Name(), Type: core.Subdomain, Value: record}
		}
		return nil
	}
	return task
}
