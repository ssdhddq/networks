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

func canRetry(opts options, attempt int, retryable bool) bool {
	if attempt >= opts.maxAttempts || !retryable {
		return false
	}

	return isIdempotent(opts.method) || opts.idempotencyKey != ""
}

func retryAfterMilliseconds(response *http.Response) (int64, bool) {
	seconds, err := strconv.ParseInt(
		strings.TrimSpace(response.Header.Get("Retry-After")),
		10,
		64,
	)
	if err != nil || seconds < 0 {
		return 0, false
	}

	const maxRetryAfterSeconds = int64((1<<63 - 1) / int64(time.Second))
	if seconds > maxRetryAfterSeconds {
		return 0, false
	}

	return seconds * 1000, true
}

func backoffLimitMilliseconds(nextAttempt int) int64 {
	if nextAttempt >= 5 {
		return 2000
	}
	return int64(200 << (nextAttempt - 1))
}

func pauseMilliseconds(response *http.Response, nextAttempt int) int64 {
	if response != nil {
		if milliseconds, ok := retryAfterMilliseconds(response); ok {
			return milliseconds
		}
	}

	return rand.Int63n(backoffLimitMilliseconds(nextAttempt) + 1)
}

func printAndSleep(milliseconds int64) {
	fmt.Printf("sleep_ms %d\n", milliseconds)
	time.Sleep(time.Duration(milliseconds) * time.Millisecond)
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

	client := &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(request *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

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

		if requestError == nil {
			_, requestError = io.Copy(io.Discard, response.Body)
			response.Body.Close()
		}

		if requestError != nil {
			fmt.Printf("attempt %d error %s\n", attempt, cleanError(requestError))
			if !canRetry(opts, attempt, true) {
				fmt.Printf("result failure attempts %d\n", attempt)
				os.Exit(1)
			}

			milliseconds := pauseMilliseconds(nil, attempt+1)
			printAndSleep(milliseconds)
			continue
		}

		fmt.Printf("attempt %d status %d\n", attempt, response.StatusCode)

		if successfulStatus(response.StatusCode) {
			fmt.Printf("result success attempts %d\n", attempt)
			return
		}
		if !canRetry(opts, attempt, retryableStatus(response.StatusCode)) {
			fmt.Printf("result failure attempts %d\n", attempt)
			os.Exit(1)
		}

		milliseconds := pauseMilliseconds(response, attempt+1)
		printAndSleep(milliseconds)
	}
}
