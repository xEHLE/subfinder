package zoomeyeapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/projectdiscovery/subfinder/v2/pkg/core"
	"github.com/projectdiscovery/subfinder/v2/pkg/session"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

// search results
type zoomeyeResults struct {
	Status int `json:"status"`
	Total  int `json:"total"`
	List   []struct {
		Name string   `json:"name"`
		Ip   []string `json:"ip"`
	} `json:"list"`
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
	s.BaseSource.SourceName = "zoomeyeapi"
	s.BaseSource.Default = false
	s.BaseSource.Recursive = false
	s.BaseSource.RequiresKey = true
	s.BaseSource.CreateTask = s.dispatcher
}

func (s *Source) dispatcher(domain string) core.Task {
	task := core.Task{
		Domain: domain,
	}
	randomApiKey := s.GetRandomKey()

	headers := map[string]string{
		"API-KEY":      randomApiKey,
		"Accept":       "application/json",
		"Content-Type": "application/json",
	}
	currentPage := 1
	api := fmt.Sprintf("https://api.zoomeye.org/domain/search?q=%s&type=1&s=1000&page=%d", domain, currentPage)
	task.RequestOpts = &session.RequestOpts{
		Method:  http.MethodGet,
		URL:     api,
		Headers: headers,
		Source:  "zoomeyeapi",
		UID:     randomApiKey,
	}

	task.OnResponse = func(t *core.Task, resp *http.Response, executor *core.Executor) error {
		defer resp.Body.Close()
		var res zoomeyeResults
		err := json.NewDecoder(resp.Body).Decode(&res)
		if err != nil {
			return err
		}
		for _, r := range res.List {
			executor.Result <- core.Result{Source: s.Name(), Type: core.Subdomain, Value: r.Name}
		}
		pages := int(res.Total/1000) + 1
		if pages > 1 {
			for i := 2; i < pages; i++ {
				tx := t.Clone()
				tx.RequestOpts.Headers["API-KEY"] = s.GetRandomKey()
				tx.RequestOpts.URL = fmt.Sprintf("https://api.zoomeye.org/domain/search?q=%s&type=1&s=1000&page=%d", domain, i)
				executor.Task <- *tx
			}
		}
		return nil
	}
	task.HasSubtasks = true
	return task
}
