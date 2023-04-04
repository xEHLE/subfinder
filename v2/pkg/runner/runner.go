package runner

import (
	"bufio"
	"context"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hako/durafmt"
	"github.com/pkg/errors"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/subfinder/v2/pkg/core"
	"github.com/projectdiscovery/subfinder/v2/pkg/passive"
	"github.com/projectdiscovery/subfinder/v2/pkg/resolve"
	"github.com/projectdiscovery/subfinder/v2/pkg/session"
)

// Runner is an instance of the subdomain enumeration
// client used to orchestrate the whole process.
type Runner struct {
	options        *Options
	passiveAgent   *passive.Agent
	resolverClient *resolve.Resolver
	executor       *core.Executor
	writers        []io.Writer
}

// NewRunner creates a new runner struct instance by parsing
// the configuration options, configuring sources, reading lists
// and setting up loggers, etc.
func NewRunner(options *Options) (*Runner, error) {
	runner := &Runner{options: options, writers: []io.Writer{options.Output}}
	if len(runner.writers) == 0 {
		// fallback to os.stdout
		runner.writers = append(runner.writers, os.Stdout)
	}

	// Initialize the passive subdomain enumeration engine
	runner.initializePassiveEngine()

	// Initialize the subdomain resolver
	err := runner.initializeResolver()
	if err != nil {
		return nil, err
	}

	runner.initExecutor()

	return runner, nil
}

func (r *Runner) initExecutor() {
	r.executor = core.NewExecutor(&core.Config{
		InputBufferSize: 10,
		TaskBufferSize:  r.options.Threads,
		MaxTasks:        r.options.Concurrency,
		Proxy:           r.options.Proxy,
		RateLimit:       r.options.RateLimit,
		Timeout:         r.options.Timeout,
	}, r.passiveAgent.TaskChan)
	// User can override any default ratelimit with this flag
	if r.options.RateLimitSource != nil {
		for _, v := range r.options.RateLimitSource {
			d := strings.SplitN(v, "=", 2)
			if len(d) == 2 {
				x, _ := strconv.Atoi(d[1])
				if x == 0 {
					continue
				}
				session.DefaultRateLimits[d[0]] = session.SourceRateLimit{
					MaxCount: uint(x),
					Duration: time.Minute,
				}
			}
		}
	}
}

// Run runs all sources and execute results
func (r *Runner) Run() error {
	wg := &sync.WaitGroup{}
	wg.Add(2)
	go r.handleInput(wg)
	go r.handleOutput(wg, r.executor.Result)

	r.executor.CreateWorkers(context.Background())
	err := r.passiveAgent.StartAll(context.Background(), r.executor.Extractor)
	if err != nil {
		return err
	}

	r.executor.Wait()
	wg.Wait()
	return nil
}

func (r *Runner) handleInput(sg *sync.WaitGroup) {
	defer sg.Done()
	var inputReader io.Reader

	if len(r.options.Domain) > 0 {
		inputReader = strings.NewReader(strings.Join(r.options.Domain, "\n"))
	}
	// If we have multiple domains as input,
	if r.options.DomainsFile != "" {
		f, err := os.Open(r.options.DomainsFile)
		if err != nil {
			gologger.Fatal().Msgf("failed to open file: %v", err)
		}
		inputReader = f
		defer f.Close()
	}
	if r.options.Stdin {
		inputReader = os.Stdin
	}

	// read input data and pass to input channel
	scanner := bufio.NewScanner(inputReader)
	ip, _ := regexp.Compile(`^([0-9\.]+$)`)
	for scanner.Scan() {
		domain, err := sanitize(scanner.Text())
		isIp := ip.MatchString(domain)
		if errors.Is(err, ErrEmptyInput) || (r.options.ExcludeIps && isIp) {
			continue
		}
		//else send to input
		r.passiveAgent.InputChan <- domain
	}
	close(r.passiveAgent.InputChan)
}

func (r *Runner) handleOutput(sg *sync.WaitGroup, resultChan chan core.Result) {
	defer sg.Done()

	// Create a unique map for filtering duplicate subdomains out
	uniqueMap := make(map[string]resolve.HostEntry)
	// Create a map to track sources for each host
	sourceMap := make(map[string]map[string]struct{})

	for {
		result, ok := <-resultChan
		if !ok {
			break
		}

		// Log errors
		if result.Error != nil {
			gologger.Warning().Msgf("Could not run source '%s': %s\n", result.Source, result.Error)
			continue
		}

		// Filter and Match Results
		subdomain := strings.ReplaceAll(strings.ToLower(result.Value), "*.", "")
		if matchSubdomain := r.filterAndMatchSubdomain(subdomain); matchSubdomain {
			// add to unique map if not present
			if _, ok := uniqueMap[subdomain]; !ok {
				sourceMap[subdomain] = make(map[string]struct{})
			}
			// Log the verbose message about the found subdomain per source
			if _, ok := sourceMap[subdomain][result.Source]; !ok {
				gologger.Verbose().Label(result.Source).Msg(subdomain)
			}
			sourceMap[subdomain][result.Source] = struct{}{}

			// Check if the subdomain is a duplicate. If not,
			// send the subdomain for resolution.
			if _, ok := uniqueMap[subdomain]; ok {
				continue
			}

			hostEntry := resolve.HostEntry{Host: subdomain, Source: result.Source}

			uniqueMap[subdomain] = hostEntry
		}
	}
	outputWriter := NewOutputWriter(r.options.JSON)
	// Now output all results in output writers
	var err error
	for _, writer := range r.writers {
		if r.options.HostIP {
			err = outputWriter.WriteHostIP(domain, foundResults, writer)
		} else {
			if r.options.RemoveWildcard {
				err = outputWriter.WriteHostNoWildcard(domain, foundResults, writer)
			} else {
				if r.options.CaptureSources {
					err = outputWriter.WriteSourceHost(domain, sourceMap, writer)
				} else {
					err = outputWriter.WriteHost(domain, uniqueMap, writer)
				}
			}
		}
		if err != nil {
			gologger.Error().Msgf("Could not write results for %s: %s\n", domain, err)
			return err
		}
	}

	// Show found subdomain count in any case.
	duration := durafmt.Parse(time.Since(now)).LimitFirstN(maxNumCount).String()
	var numberOfSubDomains int
	if r.options.RemoveWildcard {
		numberOfSubDomains = len(foundResults)
	} else {
		numberOfSubDomains = len(uniqueMap)
	}

	if r.options.ResultCallback != nil {
		for _, v := range uniqueMap {
			r.options.ResultCallback(&v)
		}
	}
	gologger.Info().Msgf("Found %d subdomains for %s in %s\n", numberOfSubDomains, domain, duration)

	if r.options.Statistics {
		gologger.Info().Msgf("Printing source statistics for %s", domain)
		printStatistics(r.passiveAgent.GetStatistics())
	}

	return nil
}

// TBD
func (r *Runner) handleWildCards() {}

// // EnumerateMultipleDomains enumerates subdomains for multiple domains
// // We keep enumerating subdomains for a given domain until we reach an error
// func (r *Runner) EnumerateMultipleDomains(reader io.Reader, writers []io.Writer) error {
// 	scanner := bufio.NewScanner(reader)
// 	ip, _ := regexp.Compile(`^([0-9\.]+$)`)
// 	for scanner.Scan() {
// 		domain, err := sanitize(scanner.Text())
// 		isIp := ip.MatchString(domain)
// 		if errors.Is(err, ErrEmptyInput) || (r.options.ExcludeIps && isIp) {
// 			continue
// 		}

// 		var file *os.File
// 		// If the user has specified an output file, use that output file instead
// 		// of creating a new output file for each domain. Else create a new file
// 		// for each domain in the directory.
// 		if r.options.OutputFile != "" {
// 			outputWriter := NewOutputWriter(r.options.JSON)
// 			file, err = outputWriter.createFile(r.options.OutputFile, true)
// 			if err != nil {
// 				gologger.Error().Msgf("Could not create file %s for %s: %s\n", r.options.OutputFile, r.options.Domain, err)
// 				return err
// 			}

// 			err = r.EnumerateSingleDomain(domain, append(writers, file))

// 			file.Close()
// 		} else if r.options.OutputDirectory != "" {
// 			outputFile := path.Join(r.options.OutputDirectory, domain)
// 			if r.options.JSON {
// 				outputFile += ".json"
// 			} else {
// 				outputFile += ".txt"
// 			}

// 			outputWriter := NewOutputWriter(r.options.JSON)
// 			file, err = outputWriter.createFile(outputFile, false)
// 			if err != nil {
// 				gologger.Error().Msgf("Could not create file %s for %s: %s\n", r.options.OutputFile, r.options.Domain, err)
// 				return err
// 			}

// 			err = r.EnumerateSingleDomain(domain, append(writers, file))

// 			file.Close()
// 		} else {
// 			err = r.EnumerateSingleDomain(domain, writers)
// 		}
// 		if err != nil {
// 			return err
// 		}
// 	}
// 	return nil
// }
