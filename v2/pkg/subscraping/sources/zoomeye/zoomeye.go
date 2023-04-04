// Package zoomeye logic
package zoomeye

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/projectdiscovery/subfinder/v2/pkg/core"
	"github.com/projectdiscovery/subfinder/v2/pkg/session"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

// zoomAuth holds the ZoomEye credentials
type zoomAuth struct {
	User string `json:"username"`
	Pass string `json:"password"`
}

type loginResp struct {
	JWT string `json:"access_token"`
}

// search results
type zoomeyeResults struct {
	Matches []struct {
		Site    string   `json:"site"`
		Domains []string `json:"domains"`
	} `json:"matches"`
}

// Source is the passive scraping agent
type Source struct {
	subscraping.BaseSource
}

// inits the source before passing to daemon
func (s *Source) Init() {
	s.BaseSource.SourceName = "zoomeye"
	s.BaseSource.Default = false
	s.BaseSource.Recursive = false
	s.BaseSource.RequiresKey = true
	s.BaseSource.CreateTask = s.dispatcher
}

func (s *Source) dispatcher(domain string) core.Task {
	task := core.Task{
		Domain: domain,
	}

	apiusername, apipassword, _ := subscraping.GetMultiPartKey(s.GetNextKey())

	creds := &zoomAuth{
		User: apiusername,
		Pass: apipassword,
	}
	body, err := json.Marshal(&creds)
	if err != nil {
		return task
	}

	task.RequestOpts = &session.RequestOpts{
		Method:  http.MethodPost,
		URL:     "https://api.zoomeye.org/user/login",
		Cookies: "application/json",
		Body:    bytes.NewBuffer(body),
		Source:  "zoomeye",
	}

	task.OnResponse = func(t *core.Task, resp *http.Response, executor *core.Executor) error {
		defer resp.Body.Close()
		var login loginResp
		err = json.NewDecoder(resp.Body).Decode(&login)
		if err != nil {
			return fmt.Errorf("failed to fetch jwt token after login: %v", err)
		}
		jwtToken := login.JWT
		if jwtToken == "" {
			return fmt.Errorf("jwt missing skipping source")
		}

		headers := map[string]string{
			"Authorization": fmt.Sprintf("JWT %s", jwtToken),
			"Accept":        "application/json",
			"Content-Type":  "application/json",
		}
		//TODO: check if it possible to fetch number of pages
		for currentPage := 0; currentPage <= 100; currentPage++ {
			tx := core.Task{
				Domain: domain,
			}
			tx.RequestOpts = &session.RequestOpts{
				Method:  http.MethodGet,
				URL:     fmt.Sprintf("https://api.zoomeye.org/web/search?query=hostname:%s&page=%d", domain, currentPage),
				Headers: headers,
				UID:     jwtToken,
				Source:  "zoomeye",
			}
			tx.OnResponse = func(t *core.Task, resp *http.Response, executor *core.Executor) error {
				defer resp.Body.Close()
				if resp.StatusCode != 200 {
					return fmt.Errorf("got %v status code expected 200", resp.StatusCode)
				}
				var res zoomeyeResults
				err := json.NewDecoder(resp.Body).Decode(&res)
				if err != nil {
					return err
				}
				for _, r := range res.Matches {
					executor.Result <- core.Result{Input: domain, Source: s.Name(), Type: core.Subdomain, Value: r.Site}
					for _, domain := range r.Domains {
						executor.Result <- core.Result{Input: domain, Source: s.Name(), Type: core.Subdomain, Value: domain}
					}
				}
				return nil
			}
			executor.Task <- tx
		}
		return nil
	}
	task.HasSubtasks = true
	return task
}
