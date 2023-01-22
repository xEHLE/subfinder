// Package dnsdb logic
package dnsdb

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"net/http"
	"strings"

	jsoniter "github.com/json-iterator/go"
	"github.com/projectdiscovery/subfinder/v2/pkg/core"
	"github.com/projectdiscovery/subfinder/v2/pkg/session"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

type dnsdbResponse struct {
	Name string `json:"rrname"`
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
	s.BaseSource.SourceName = "dnsdb"
	s.BaseSource.Default = false
	s.BaseSource.Recursive = false
	s.BaseSource.RequiresKey = true
	s.BaseSource.CreateTask = s.dispatcher
}

// Run function returns all subdomains found with the service
func (s *Source) dispatcher(domain string) core.Task {
	task := core.Task{
		Domain: domain,
	}

	randomApiKey := s.GetRandomKey()

	headers := map[string]string{
		"X-API-KEY":    randomApiKey,
		"Accept":       "application/json",
		"Content-Type": "application/json",
	}

	task.RequestOpts = &session.RequestOpts{
		Method:  http.MethodGet,
		URL:     fmt.Sprintf("https://api.dnsdb.info/lookup/rrset/name/*.%s?limit=1000000000000", domain),
		Headers: headers,
		Source:  "dnsdb",
		UID:     randomApiKey,
	}

	task.OnResponse = func(t *core.Task, resp *http.Response, executor *core.Executor) error {
		defer resp.Body.Close()
		scanner := bufio.NewScanner(resp.Body)
		for scanner.Scan() {
			line := scanner.Text()
			if line == "" {
				continue
			}
			var response dnsdbResponse
			err := jsoniter.NewDecoder(bytes.NewBufferString(line)).Decode(&response)
			if err != nil {
				return err
			}
			executor.Result <- core.Result{
				Source: s.Name(), Type: core.Subdomain, Value: strings.TrimSuffix(response.Name, "."),
			}
		}
		return nil
	}
	return task
}
