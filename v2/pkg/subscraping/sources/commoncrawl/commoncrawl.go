// Package commoncrawl logic
package commoncrawl

import (
	"bufio"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	jsoniter "github.com/json-iterator/go"

	"github.com/projectdiscovery/subfinder/v2/pkg/core"
	"github.com/projectdiscovery/subfinder/v2/pkg/session"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

const (
	indexURL     = "https://index.commoncrawl.org/collinfo.json"
	maxYearsBack = 5
)

var year = time.Now().Year()

type indexResponse struct {
	ID     string `json:"id"`
	APIURL string `json:"cdx-api"`
}

// Source is the passive scraping agent
type Source struct {
	subscraping.BaseSource
}

// inits the source before passing to daemon
func (s *Source) Init() {
	s.BaseSource.SourceName = "commoncrawl"
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
		URL:    indexURL,
		Source: "commoncrawl",
	}

	// search page response
	task.OnResponse = func(t *core.Task, resp *http.Response, executor *core.Executor) error {
		defer resp.Body.Close()

		var indexes []indexResponse
		err := jsoniter.NewDecoder(resp.Body).Decode(&indexes)
		if err != nil {
			return err
		}
		years := make([]string, 0)
		for i := 0; i < maxYearsBack; i++ {
			years = append(years, strconv.Itoa(year-i))
		}

		searchIndexes := make(map[string]string)
		for _, year := range years {
			for _, index := range indexes {
				if strings.Contains(index.ID, year) {
					if _, ok := searchIndexes[year]; !ok {
						searchIndexes[year] = index.APIURL
						break
					}
				}
			}
		}
		// get subdomains
		for _, apiURL := range searchIndexes {
			executor.Task <- getSubdomains(apiURL, t.Domain)
		}
		return nil
	}
	task.HasSubtasks = true
	return task
}

func getSubdomains(searchURL, domain string) core.Task {
	task := core.Task{
		Domain: domain,
	}
	task.RequestOpts = &session.RequestOpts{
		Method:  http.MethodGet,
		URL:     fmt.Sprintf("%s?url=*.%s", searchURL, domain),
		Headers: map[string]string{"Host": "index.commoncrawl.org"},
		Source:  "commoncrawl",
	}
	task.OnResponse = func(t *core.Task, resp *http.Response, executor *core.Executor) error {
		defer resp.Body.Close()
		scanner := bufio.NewScanner(resp.Body)
		for scanner.Scan() {
			line := scanner.Text()
			if line == "" {
				continue
			}
			line, _ = url.QueryUnescape(line)
			subdomain := executor.Extractor.Get(t.Domain).FindString(line)
			if subdomain != "" {
				// fix for triple encoded URL
				subdomain = strings.ToLower(subdomain)
				subdomain = strings.TrimPrefix(subdomain, "25")
				subdomain = strings.TrimPrefix(subdomain, "2f")

				executor.Result <- core.Result{Input: domain, Source: t.RequestOpts.Source, Type: core.Subdomain, Value: subdomain}
			}
		}
		return nil
	}
	return task
}
