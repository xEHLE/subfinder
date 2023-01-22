package chinaz

// chinaz  http://my.chinaz.com/ChinazAPI/DataCenter/MyDataApi
import (
	"context"
	"fmt"
	"io"
	"net/http"

	jsoniter "github.com/json-iterator/go"
	"github.com/projectdiscovery/subfinder/v2/pkg/core"
	"github.com/projectdiscovery/subfinder/v2/pkg/session"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

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
	s.BaseSource.SourceName = "chinaz"
	s.BaseSource.Recursive = false
	s.BaseSource.Default = true
	s.BaseSource.RequiresKey = true
	s.BaseSource.CreateTask = s.dispatcher
}

func (s *Source) dispatcher(domain string) core.Task {
	task := core.Task{}

	randomApiKey := s.BaseSource.GetRandomKey()

	task.RequestOpts = &session.RequestOpts{
		Method: http.MethodGet,
		URL:    fmt.Sprintf("https://apidatav2.chinaz.com/single/alexa?key=%s&domain=%s", randomApiKey, domain),
		Source: "chinaz",
		UID:    randomApiKey,
	}

	task.OnResponse = func(t *core.Task, resp *http.Response, executor *core.Executor) error {
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		SubdomainList := jsoniter.Get(body, "Result").Get("ContributingSubdomainList")
		if SubdomainList.ToBool() {
			_data := []byte(SubdomainList.ToString())
			for i := 0; i < SubdomainList.Size(); i++ {
				subdomain := jsoniter.Get(_data, i, "DataUrl").ToString()
				executor.Result <- core.Result{Source: "chinaz", Type: core.Subdomain, Value: subdomain}
			}
		}
		return nil
	}
	return task
}
