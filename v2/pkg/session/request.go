package session

import (
	"context"
	"io"
	"net/http"

	"github.com/corpix/uarand"
)

// BasicAuth request's Authorization header
type BasicAuth struct {
	Username string
	Password string
}

// Options contains request options
type RequestOpts struct {
	Method      string
	URL         string
	Cookies     string
	Headers     map[string]string
	ContentType string
	Body        io.Reader
	Source      string
	UID         string             // API Key (used for UID) in ratelimit
	Cancel      context.CancelFunc // cancel source
	BasicAuth   BasicAuth          // Basic Auth
}

func (o *RequestOpts) getRequest(ctx context.Context) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, o.Method, o.URL, o.Body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", uarand.GetRandom())
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Language", "en")
	req.Header.Set("Connection", "close")

	if o.BasicAuth.Username != "" || o.BasicAuth.Password != "" {
		req.SetBasicAuth(o.BasicAuth.Username, o.BasicAuth.Password)
	}

	if o.Cookies != "" {
		req.Header.Set("Cookie", o.Cookies)
	}
	if o.Headers != nil {
		for k, v := range o.Headers {
			req.Header.Add(k, v)
		}
	}
	if o.ContentType != "" {
		req.Header.Add("Content-Type", o.ContentType)
	}

	return req, nil
}
