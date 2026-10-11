package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

type header struct {
	name  string
	value string
}

type message struct {
	isRequest bool
	method    string
	target    string
	status    string
	reason    string
	headers   []header
	body      []byte
}

type headerInfo struct {
	headers          []header
	contentLength    uint64
	hasContentLength bool
	chunked          bool
}

func isTokenByte(b byte) bool {
	if b >= '0' && b <= '9' || b >= 'A' && b <= 'Z' || b >= 'a' && b <= 'z' {
		return true
	}
	return strings.ContainsRune("!#$%&'*+-.^_`|~", rune(b))
}

func parseStartLine(line []byte) (message, string) {
	text := string(line)
	if strings.HasPrefix(text, "HTTP/") {
		parts := strings.SplitN(text, " ", 3)
		if len(parts) < 2 || parts[0] != "HTTP/1.1" || len(parts[1]) != 3 {
			return message{}, "bad_start_line"
		}
		for _, digit := range parts[1] {
			if digit < '0' || digit > '9' {
				return message{}, "bad_start_line"
			}
		}
		reason := ""
		if len(parts) == 3 {
			reason = parts[2]
		}
		return message{status: parts[1], reason: reason}, ""
	}

	parts := strings.Split(text, " ")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] != "HTTP/1.1" {
		return message{}, "bad_start_line"
	}
	for i := 0; i < len(parts[0]); i++ {
		if !isTokenByte(parts[0][i]) {
			return message{}, "bad_start_line"
		}
	}
	return message{isRequest: true, method: parts[0], target: parts[1]}, ""
}

func parseHeaders(data []byte) (headerInfo, string) {
	if len(data) == 0 {
		return headerInfo{}, ""
	}

	var result headerInfo
	for _, line := range bytes.Split(data, []byte("\r\n")) {
		colon := bytes.IndexByte(line, ':')
		if colon <= 0 {
			return headerInfo{}, "bad_header"
		}

		nameBytes := line[:colon]
		for _, character := range nameBytes {
			if !isTokenByte(character) {
				return headerInfo{}, "bad_header"
			}
		}

		valueBytes := line[colon+1:]
		for _, character := range valueBytes {
			if (character < 0x20 && character != '\t') || character == 0x7f {
				return headerInfo{}, "bad_header"
			}
		}

		name := strings.ToLower(string(nameBytes))
		value := strings.Trim(string(valueBytes), " \t")
		result.headers = append(result.headers, header{name: name, value: value})

		switch name {
		case "content-length":
			if value == "" {
				return headerInfo{}, "bad_header"
			}
			for _, character := range value {
				if character < '0' || character > '9' {
					return headerInfo{}, "bad_header"
				}
			}

			parsed, err := strconv.ParseUint(value, 10, 64)
			if err != nil {
				return headerInfo{}, "bad_header"
			}
			if result.hasContentLength && result.contentLength != parsed {
				return headerInfo{}, "bad_header"
			}

			result.contentLength = parsed
			result.hasContentLength = true

		case "transfer-encoding":
			for _, coding := range strings.Split(value, ",") {
				if strings.EqualFold(strings.TrimSpace(coding), "chunked") {
					result.chunked = true
				}
			}
		}
	}

	return result, ""
}

func parseChunked(data []byte) ([]byte, string) {
	var body []byte
	offset := 0
	for {
		lineEndRelative := bytes.Index(data[offset:], []byte("\r\n"))
		if lineEndRelative < 0 {
			return nil, "bad_chunk"
		}
		lineEnd := offset + lineEndRelative
		sizeText := string(data[offset:lineEnd])
		if extension := strings.IndexByte(sizeText, ';'); extension >= 0 {
			sizeText = sizeText[:extension]
		}
		sizeText = strings.TrimSpace(sizeText)

		if sizeText == "" {
			return nil, "bad_chunk"
		}
		size, err := strconv.ParseUint(sizeText, 16, 64)
		if err != nil {
			return nil, "bad_chunk"
		}
		offset = lineEnd + 2

		if size == 0 {

			for {
				trailerEndRelative := bytes.Index(data[offset:], []byte("\r\n"))

				if trailerEndRelative < 0 {
					return nil, "bad_chunk"
				}
				trailerEnd := offset + trailerEndRelative
				offset = trailerEnd + 2
				if trailerEndRelative == 0 {
					return body, ""
				}
			}
		}

		if size > uint64(len(data)-offset) {
			return nil, "bad_chunk"
		}
		end := offset + int(size)

		if end+2 > len(data) || !bytes.Equal(data[end:end+2], []byte("\r\n")) {
			return nil, "bad_chunk"
		}
		body = append(body, data[offset:end]...)
		offset = end + 2
	}
}

func parse(data []byte) (message, string) {
	startEnd := bytes.Index(data, []byte("\r\n"))
	if startEnd < 0 {
		return message{}, "bad_start_line"
	}
	result, problem := parseStartLine(data[:startEnd])

	if problem != "" {
		return message{}, problem
	}

	headersStart := startEnd + 2
	headersEnd := 0
	bodyStart := 0

	if bytes.HasPrefix(data[headersStart:], []byte("\r\n")) {
		headersEnd = headersStart
		bodyStart = headersStart + 2
	} else {
		headersEndRelative := bytes.Index(data[headersStart:], []byte("\r\n\r\n"))
		if headersEndRelative < 0 {
			return message{}, "bad_header"

		}
		headersEnd = headersStart + headersEndRelative
		bodyStart = headersEnd + 4
	}

	parsedHeaders, problem := parseHeaders(data[headersStart:headersEnd])
	if problem != "" {
		return message{}, problem
	}
	result.headers = parsedHeaders.headers

	bodyData := data[bodyStart:]

	if parsedHeaders.chunked {
		body, problem := parseChunked(bodyData)
		if problem != "" {

			return message{}, problem
		}
		result.body = body
		return result, ""
	}
	if parsedHeaders.hasContentLength {
		if parsedHeaders.contentLength > uint64(len(bodyData)) {
			return message{}, "incomplete_body"
		}
		result.body = bodyData[:int(parsedHeaders.contentLength)]
	}
	return result, ""
}

func printable(data []byte) bool {

	for _, character := range data {
		if character < 0x20 || character > 0x7e {
			return false
		}
	}
	return true
}

func main() {
	data, err := io.ReadAll(os.Stdin)

	if err != nil {
		fmt.Println("error bad_start_line")
		os.Exit(1)
	}
	result, problem := parse(data)
	if problem != "" {
		fmt.Println("error", problem)
		os.Exit(1)
	}

	if result.isRequest {
		fmt.Println("type request")
		fmt.Println("method", result.method)
		fmt.Println("target", result.target)
	} else {
		fmt.Println("type response")
		fmt.Println("status", result.status)
		fmt.Println("reason", result.reason)
	}
	fmt.Println("version HTTP/1.1")
	for _, field := range result.headers {
		fmt.Println("header", field.name, field.value)
	}
	fmt.Println("body.length", len(result.body))
	if len(result.body) > 0 && printable(result.body) {
		fmt.Println("body.text", string(result.body))
	}
}
