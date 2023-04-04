// Package rapiddns is a RapidDNS Scraping Engine in Golang
package rapiddns

import (
	"io"
	"net/http"

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
	s.BaseSource.SourceName = "rapiddns"
	s.BaseSource.Default = false
	s.BaseSource.Recursive = false
	s.BaseSource.RequiresKey = false
	s.BaseSource.CreateTask = s.dispatcher
}

func (s *Source) dispatcher(domain string) core.Task {
	task := core.Task{
		Domain: domain,
	}
	task.RequestOpts = &session.RequestOpts{
		Method: http.MethodGet,
		URL:    "https://rapiddns.io/subdomain/" + domain + "?full=1",
		Source: "rapiddns",
	}
	task.OnResponse = func(t *core.Task, resp *http.Response, executor *core.Executor) error {
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		src := string(body)
		for _, subdomain := range executor.Extractor.Get(domain).FindAllString(src, -1) {
			executor.Result <- core.Result{Input: domain, Source: s.Name(), Type: core.Subdomain, Value: subdomain}
		}
		return nil
	}
	return task
}
