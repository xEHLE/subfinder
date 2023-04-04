// Package dnsdumpster logic
package dnsdumpster

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/projectdiscovery/subfinder/v2/pkg/core"
	"github.com/projectdiscovery/subfinder/v2/pkg/session"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

// CSRFSubMatchLength CSRF regex submatch length
const CSRFSubMatchLength = 2

var re = regexp.MustCompile("<input type=\"hidden\" name=\"csrfmiddlewaretoken\" value=\"(.*)\">")

// getCSRFToken gets the CSRF Token from the page
func getCSRFToken(page string) string {
	if subs := re.FindStringSubmatch(page); len(subs) == CSRFSubMatchLength {
		return strings.TrimSpace(subs[1])
	}
	return ""
}

// postForm posts a form for a domain and returns the response
func postForm(domain string, token string) core.Task {
	task := core.Task{
		Domain: domain,
	}
	params := url.Values{
		"csrfmiddlewaretoken": {token},
		"targetip":            {domain},
		"user":                {"free"},
	}
	task.RequestOpts = &session.RequestOpts{
		Method:  http.MethodPost,
		URL:     "https://dnsdumpster.com/",
		Cookies: fmt.Sprintf("csrftoken=%s; Domain=dnsdumpster.com", token),
		Headers: map[string]string{
			"Content-Type": "application/x-www-form-urlencoded",
			"Referer":      "https://dnsdumpster.com",
			"X-CSRF-Token": token,
		},
		Body:      strings.NewReader(params.Encode()),
		BasicAuth: session.BasicAuth{},
		Source:    "dnsdumpster",
	}

	task.OnResponse = func(t *core.Task, resp *http.Response, executor *core.Executor) error {
		defer resp.Body.Close()
		in, err := io.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		data := string(in)
		for _, subdomain := range executor.Extractor.Get(domain).FindAllString(data, -1) {
			executor.Result <- core.Result{Input: domain, Source: "dnsdumpster", Type: core.Subdomain, Value: subdomain}
		}
		return nil
	}
	return task
}

// Source is the passive scraping agent
type Source struct {
	subscraping.BaseSource
}

// inits the source before passing to daemon
func (s *Source) Init() {
	s.BaseSource.SourceName = "dnsdumpster"
	s.BaseSource.Default = false
	s.BaseSource.Recursive = true
	s.BaseSource.RequiresKey = false
	s.BaseSource.CreateTask = s.dispatcher
}

// Run function returns all subdomains found with the service
func (s *Source) dispatcher(domain string) core.Task {
	task := core.Task{
		Domain: domain,
	}

	task.RequestOpts = &session.RequestOpts{
		Method: http.MethodGet,
		URL:    "https://dnsdumpster.com/",
		Source: s.SourceName,
	}

	task.OnResponse = func(t *core.Task, resp *http.Response, executor *core.Executor) error {
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		resp.Body.Close()
		csrfToken := getCSRFToken(string(body))
		if csrfToken == "" {
			return fmt.Errorf("failed to fetch csrf token")
		} else {
			executor.Task <- postForm(domain, csrfToken)
			return nil
		}
	}
	task.HasSubtasks = true
	return task
}
