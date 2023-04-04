package hunter

import (
	"encoding/base64"
	"fmt"
	"net/http"

	jsoniter "github.com/json-iterator/go"
	"github.com/projectdiscovery/subfinder/v2/pkg/core"
	"github.com/projectdiscovery/subfinder/v2/pkg/session"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

type hunterResp struct {
	Code    int        `json:"code"`
	Data    hunterData `json:"data"`
	Message string     `json:"message"`
}

type infoArr struct {
	URL      string `json:"url"`
	IP       string `json:"ip"`
	Port     int    `json:"port"`
	Domain   string `json:"domain"`
	Protocol string `json:"protocol"`
}

type hunterData struct {
	InfoArr []infoArr `json:"arr"`
	Total   int       `json:"total"`
}

// Source is the passive scraping agent
type Source struct {
	subscraping.BaseSource
}

// inits the source before passing to daemon
func (s *Source) Init() {
	s.BaseSource.SourceName = "hunter"
	s.BaseSource.Recursive = false
	s.BaseSource.Default = true
	s.BaseSource.RequiresKey = true
	s.BaseSource.CreateTask = s.dispatcher
}

func (s *Source) dispatcher(domain string) core.Task {
	task := core.Task{
		Domain: domain,
	}
	randomApiKey := s.GetNextKey()

	// hunter api doc https://hunter.qianxin.com/home/helpCenter?r=5-1-2
	qbase64 := base64.URLEncoding.EncodeToString([]byte(fmt.Sprintf("domain=\"%s\"", domain)))
	page := 1
	task.RequestOpts = &session.RequestOpts{
		Method: http.MethodGet,
		URL:    fmt.Sprintf("https://hunter.qianxin.com/openApi/search?api-key=%s&search=%s&page=%v&page_size=100&is_web=3", randomApiKey, qbase64, page),
		Source: "hunter",
		UID:    randomApiKey,
	}

	task.OnResponse = func(t *core.Task, resp *http.Response, executor *core.Executor) error {
		defer resp.Body.Close()
		var response hunterResp
		err := jsoniter.NewDecoder(resp.Body).Decode(&response)
		if err != nil {
			return err
		}
		if response.Code == 401 || response.Code == 400 {
			return fmt.Errorf("%s", response.Message)
		}
		if response.Data.Total > 0 {
			for _, hunterInfo := range response.Data.InfoArr {
				subdomain := hunterInfo.Domain
				executor.Result <- core.Result{Input: domain, Source: "hunter", Type: core.Subdomain, Value: subdomain}
			}
		}
		pages := int(response.Data.Total/1000) + 1
		if pages > 1 {
			for i := 2; i < pages; i++ {
				tx := t.Clone()
				randomApiKey := s.GetNextKey()
				tx.RequestOpts.URL = fmt.Sprintf("https://hunter.qianxin.com/openApi/search?api-key=%s&search=%s&page=%v&page_size=100&is_web=3", randomApiKey, qbase64, page)
				executor.Task <- task
			}
		}
		return nil
	}
	task.HasSubtasks = true
	return task
}
