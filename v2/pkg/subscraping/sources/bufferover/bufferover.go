// Package bufferover is a bufferover Scraping Engine in Golang
package bufferover

import (
	"fmt"
	"net/http"
	"strings"

	jsoniter "github.com/json-iterator/go"

	"github.com/projectdiscovery/subfinder/v2/pkg/core"
	"github.com/projectdiscovery/subfinder/v2/pkg/session"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

type response struct {
	Meta struct {
		Errors []string `json:"Errors"`
	} `json:"Meta"`
	FDNSA   []string `json:"FDNS_A"`
	RDNS    []string `json:"RDNS"`
	Results []string `json:"Results"`
}

// Source is the passive scraping agent
type Source struct {
	subscraping.BaseSource
}

// inits the source before passing to daemon
func (s *Source) Init() {
	s.BaseSource.SourceName = "bufferover"
	s.BaseSource.Default = true
	s.BaseSource.Recursive = true
	s.BaseSource.RequiresKey = true
	s.BaseSource.CreateTask = s.dispatcher
}

// Run function returns all subdomains found with the service
func (s *Source) dispatcher(domain string) core.Task {
	task := core.Task{
		Domain: domain,
	}
	randomApiKey := s.BaseSource.GetNextKey()

	task.RequestOpts = &session.RequestOpts{
		Method:  http.MethodGet,
		URL:     fmt.Sprintf("https://tls.bufferover.run/dns?q=.%s", domain),
		Headers: map[string]string{"x-api-key": randomApiKey},
		Source:  "bufferover",
		UID:     randomApiKey,
	}

	task.OnResponse = func(t *core.Task, resp *http.Response, executor *core.Executor) error {
		defer resp.Body.Close()
		var bufforesponse response
		err := jsoniter.NewDecoder(resp.Body).Decode(&bufforesponse)
		if err != nil {
			return err
		}
		metaErrors := bufforesponse.Meta.Errors
		if len(metaErrors) > 0 {
			return fmt.Errorf("%s", strings.Join(metaErrors, ", "))
		}

		var subdomains []string
		if len(bufforesponse.FDNSA) > 0 {
			subdomains = bufforesponse.FDNSA
			subdomains = append(subdomains, bufforesponse.RDNS...)
		} else if len(bufforesponse.Results) > 0 {
			subdomains = bufforesponse.Results
		}

		for _, subdomain := range subdomains {
			for _, value := range executor.Extractor.Get(t.Domain).FindAllString(subdomain, -1) {
				executor.Result <- core.Result{Input: domain, Source: "bufferover", Type: core.Subdomain, Value: value}
			}
		}
		return nil
	}
	return task
}
