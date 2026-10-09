package main

import (
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

type options struct {
	resource       string
	method         string
	maxAttempts    int
	idempotencyKey string
}

func parseOptions(args []string) (options, error) {
	if len(args) < 1 {
		return options{}, fmt.Errorf("resource URL is required")
	}
	result := options{resource: args[0], method: "GET", maxAttempts: 5}
	for i := 1; i < len(args); i++ {
		if i+1 >= len(args) {
			return options{}, fmt.Errorf("option %s requires a value", args[i])
		}
		value := args[i+1]
		switch args[i] {
		case "--method":
			result.method = strings.ToUpper(value)
		case "--max-attempts":
			attempts, err := strconv.Atoi(value)
			if err != nil || attempts < 1 {
				return options{}, fmt.Errorf(" max attempts a positive integer")
			}
			result.maxAttempts = attempts
		case "--idempotency-key":
			result.idempotencyKey = value
		default:
			return options{}, fmt.Errorf("unknown option %s", args[i])
		}
		i++
	}

	parsed, err := url.Parse(result.resource)
	if err != nil || parsed.Scheme != "http" || parsed.Host == "" {
		return options{}, fmt.Errorf("resource a complete http URL")
	}
	return result, nil
}

func isIdempotent(method string) bool {
	switch method {
	case "GET", "HEAD", "PUT", "DELETE", "OPTIONS", "TRACE":
		return true
	default:
		return false
	}
}

func retryableStatus(status int) bool {
	switch status {
	case 429, 500, 502, 503, 504:
		return true
	default:
		return false
	}
}

func successfulStatus(status int) bool {
	return status >= 200 && status <= 399
}

func retryAfter(response *http.Response) (time.Duration, bool) {
	seconds, err := strconv.ParseInt(strings.TrimSpace(response.Header.Get("Retry-After")), 10, 64)
	if err != nil || seconds < 0 {
		return 0, false
	}
	return time.Duration(seconds) * time.Second, true
}

func nextBackoff(n int) time.Duration {
	milliseconds := 200
	for attempt := 1; attempt < n; attempt++ {
		if milliseconds >= 2000 {
			return 2000 * time.Millisecond
		}
		milliseconds *= 2
		if milliseconds > 2000 {
			milliseconds = 2000
		}
	}
	return time.Duration(milliseconds) * time.Millisecond
}

func cleanError(err error) string {
	return strings.NewReplacer("\n", " ", "\r", " ").Replace(err.Error())
}

func main() {
	opts, err := parseOptions(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}

	client := &http.Client{Timeout: 5 * time.Second}
	random := rand.New(rand.NewSource(time.Now().UnixNano()))

	for attempt := 1; attempt <= opts.maxAttempts; attempt++ {
		request, err := http.NewRequest(opts.method, opts.resource, nil)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
		request.Close = true
		if opts.idempotencyKey != "" {
			request.Header.Set("Idempotency-Key", opts.idempotencyKey)
		}

		response, requestError := client.Do(request)

		var retryPause time.Duration
		hasRetryAfter := false

		if requestError == nil {
			retryPause, hasRetryAfter = retryAfter(response)

			_, requestError = io.Copy(io.Discard, response.Body)
			response.Body.Close()
		}

		if requestError != nil {
			fmt.Printf("attempt %d error %s\n", attempt, cleanError(requestError))
			if attempt == opts.maxAttempts || (!isIdempotent(opts.method) && opts.idempotencyKey == "") {
				fmt.Printf("result failure attempts %d\n", attempt)
				os.Exit(1)
			}
			pause := time.Duration(random.Int63n(int64(nextBackoff(attempt+1)) + 1))
			fmt.Printf("sleep_ms %d\n", pause.Milliseconds())
			time.Sleep(pause)
			continue
		}

		fmt.Printf("attempt %d status %d\n", attempt, response.StatusCode)

		if successfulStatus(response.StatusCode) {
			fmt.Printf("result success attempts %d\n", attempt)
			return
		}
		canRetry := retryableStatus(response.StatusCode) && attempt < opts.maxAttempts
		if !isIdempotent(opts.method) && opts.idempotencyKey == "" {
			canRetry = false
		}
		if !canRetry {
			fmt.Printf("result failure attempts %d\n", attempt)
			os.Exit(1)
		}

		if hasRetryAfter {
			fmt.Printf("sleep_ms %d\n", retryPause.Milliseconds())
			time.Sleep(retryPause)
			continue
		}
		pause := time.Duration(random.Int63n(int64(nextBackoff(attempt+1)) + 1))
		fmt.Printf("sleep_ms %d\n", pause.Milliseconds())
		time.Sleep(pause)
	}
}
