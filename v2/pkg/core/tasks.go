package core

import (
	"context"
	"net/http"
	"time"

	"github.com/projectdiscovery/subfinder/v2/pkg/session"
)

// Task is  bundle of options and functions that is created by
// a source and executed by workers in worker group
type Task struct {
	Domain      string
	HasSubtasks bool
	Metdata     any                                                          // Optional metdata
	ExecTime    time.Duration                                                // Time taken to execute this task
	RequestOpts *session.RequestOpts                                         // Request Options
	Override    func(t *Task, ctx context.Context, executor *Executor) error // Override ignores defined execution methodology and executes task if err is not nil default is executed
	OnResponse  func(t *Task, resp *http.Response, executor *Executor) error // On Response
	Cleanup     func()                                                       // Any CleanUp if necessary executed using defer
}

// Executes given task
func (t *Task) Execute(ctx context.Context, e *Executor) {
	defer func(start time.Time) {
		t.ExecTime = time.Since(start)
	}(time.Now())
	// cleanup if available
	defer func() {
		if t.Cleanup != nil {
			t.Cleanup()
		}
	}()

	if t.Override != nil {
		err := t.Override(t, ctx, e)
		if err == nil {
			return
		}
	}

	resp, err := e.Session.Do(ctx, t.RequestOpts)
	if err != nil && resp == nil {
		e.Result <- Result{
			Source: t.RequestOpts.Source, Type: Error, Error: err,
		}
		e.Session.DiscardHTTPResponse(resp)
		return
	}
	err = t.OnResponse(t, resp, e)
	if err != nil {
		e.Result <- Result{
			Source: t.RequestOpts.Source, Type: Error, Error: err,
		}
	}
}

// Clone // cross check
func (t *Task) Clone() *Task {
	req := *t.RequestOpts
	task := Task{
		Domain:      t.Domain,
		RequestOpts: &req,
		OnResponse:  t.OnResponse,
		Override:    t.Override,
	}
	return &task
}
