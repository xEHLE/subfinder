// Package censys logic
package censys

import (
	"bytes"
	"fmt"
	"math"
	"net/http"
	"strconv"

	jsoniter "github.com/json-iterator/go"

	"github.com/projectdiscovery/subfinder/v2/pkg/core"
	"github.com/projectdiscovery/subfinder/v2/pkg/session"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

const maxCensysPages = 10

type resultsq struct {
	Data  []string `json:"parsed.extensions.subject_alt_name.dns_names"`
	Data1 []string `json:"parsed.names"`
}

type response struct {
	Results  []resultsq `json:"results"`
	Metadata struct {
		Pages int `json:"pages"`
	} `json:"metadata"`
}

// Source is the passive scraping agent
type Source struct {
	subscraping.BaseSource
}

// inits the source before passing to daemon
func (s *Source) Init() {
	s.BaseSource.SourceName = "censys"
	s.BaseSource.Recursive = false
	s.BaseSource.Default = true
	s.BaseSource.RequiresKey = true
	s.BaseSource.CreateTask = s.dispatcher
}

// Run function returns all subdomains found with the service
func (s *Source) dispatcher(domain string) core.Task {
	task := core.Task{
		Domain: domain,
	}
	apitoken, apisecret, _ := subscraping.GetMultiPartKey(s.GetNextKey())
	task.RequestOpts = &session.RequestOpts{
		Method:    http.MethodPost,
		URL:       "https://search.censys.io/api/v1/search/certificates",
		Headers:   map[string]string{"Content-Type": "application/json", "Accept": "application/json"},
		Body:      getRequestBody(domain, 1),
		BasicAuth: session.BasicAuth{Username: apitoken, Password: apisecret},
		Source:    "censys",
		UID:       apitoken,
	}
	task.Metdata = 1
	task.OnResponse = func(t *core.Task, resp *http.Response, executor *core.Executor) error {
		defer resp.Body.Close()
		var censysResponse response
		err := jsoniter.NewDecoder(resp.Body).Decode(&censysResponse)
		if err != nil {
			return err
		}

		re := executor.Extractor.Get(domain)
		results := re.FindAllString(fmt.Sprint(censysResponse.Results), -1)
		for _, v := range results {
			executor.Result <- core.Result{Input: domain, Source: t.RequestOpts.Source, Type: core.Subdomain, Value: v}
		}
		// fetch next pages
		if currentPage, ok := t.Metdata.(int); ok {
			minfloat := math.Min(float64(censysResponse.Metadata.Pages), maxCensysPages)
			min := int(minfloat)
			if currentPage < min {
				for currentPage < min {
					currentPage++
					newtask := t.Clone()
					t.Metdata = currentPage
					newtask.RequestOpts.Body = getRequestBody(t.Domain, currentPage)
					executor.Task <- *newtask
				}
			}
		}
		return nil
	}
	task.HasSubtasks = true
	return task
}

func getRequestBody(domain string, currentPage int) *bytes.Reader {
	body := []byte(`{"query":"` + domain + `", "page":` + strconv.Itoa(currentPage) + `, "fields":["parsed.names","parsed.extensions.subject_alt_name.dns_names"], "flatten":true}`)
	return bytes.NewReader(body)
}
