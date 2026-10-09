package main

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	typeA     uint16 = 1
	typeNS    uint16 = 2
	typeCNAME uint16 = 5
	typeMX    uint16 = 15
	typeTXT   uint16 = 16
	typeAAAA  uint16 = 28
)

var typeCodes = map[string]uint16{
	"A":     typeA,
	"AAAA":  typeAAAA,
	"CNAME": typeCNAME,
	"MX":    typeMX,
	"TXT":   typeTXT,
	"NS":    typeNS,
}

var typeNames = map[uint16]string{
	typeA:     "A",
	typeAAAA:  "AAAA",
	typeCNAME: "CNAME",
	typeMX:    "MX",
	typeTXT:   "TXT",
	typeNS:    "NS",
}

type answer struct {
	typeName string
	value    string
	ttl      uint32
}

type response struct {
	rcode       int
	answers     []answer
	recordCount int
	minTTL      uint32
}

type cacheEntry struct {
	answers []answer
	expires time.Time
}

func u16(b []byte) uint16 {
	return uint16(b[0])<<8 | uint16(b[1])
}

func u32(b []byte) uint32 {
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

func putU16(dst []byte, value uint16) {
	dst[0] = byte(value >> 8)
	dst[1] = byte(value)
}

func encodeName(name string) ([]byte, error) {
	name = strings.TrimSuffix(name, ".")
	if name == "" {
		return []byte{0}, nil
	}

	labels := strings.Split(name, ".")
	encoded := make([]byte, 0, len(name)+2)
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 {
			return nil, fmt.Errorf("invalid DNS %q", label)
		}
		encoded = append(encoded, byte(len(label)))

		encoded = append(encoded, []byte(label)...)
	}
	encoded = append(encoded, 0)
	if len(encoded) > 255 {
		return nil, errors.New("DNS > 255")
	}
	return encoded, nil
}

func buildQuery(id, qtype uint16, name string) ([]byte, error) {
	qname, err := encodeName(name)
	if err != nil {
		return nil, err
	}
	packet := make([]byte, 12+len(qname)+4)
	putU16(packet[0:2], id)
	putU16(packet[2:4], 0x0100)
	putU16(packet[4:6], 1)
	copy(packet[12:], qname)
	offset := 12 + len(qname)
	putU16(packet[offset:offset+2], qtype)
	putU16(packet[offset+2:offset+4], 1)
	return packet, nil
}

func readName(message []byte, offset int) (string, int, error) {
	labels := make([]string, 0)
	next := offset
	jumped := false
	visited := make(map[int]bool)

	for {
		if offset >= len(message) {
			return "", 0, errors.New("DNS name runs past the message")
		}
		if visited[offset] {
			return "", 0, errors.New("DNS compression pointer loop")
		}
		visited[offset] = true

		length := message[offset]
		if length&0xc0 == 0xc0 {
			if offset+1 >= len(message) {
				return "", 0, errors.New("truncated DNS")
			}
			pointer := int(length&0x3f)<<8 | int(message[offset+1])
			if pointer >= len(message) {
				return "", 0, errors.New("DNS pointer outside")
			}
			if !jumped {
				next = offset + 2
				jumped = true
			}
			offset = pointer
			continue
		}
		if length&0xc0 != 0 {
			return "", 0, errors.New("not DNS label encoding")
		}
		if length == 0 {
			if !jumped {
				next = offset + 1
			}
			if len(labels) == 0 {
				return ".", next, nil
			}
			return strings.Join(labels, ".") + ".", next, nil
		}

		start := offset + 1
		end := start + int(length)
		if end > len(message) {
			return "", 0, errors.New("truncated DNS label")
		}
		labels = append(labels, string(message[start:end]))
		offset = end
		if !jumped {
			next = offset
		}
	}
}

func skipQuestions(message []byte, count uint16) (int, error) {
	offset := 12
	for i := 0; i < int(count); i++ {
		_, next, err := readName(message, offset)
		if err != nil {
			return 0, err
		}
		if next+4 > len(message) {
			return 0, errors.New("truncated DNS question")
		}
		offset = next + 4 // QTYPE and QCLASS.
	}
	return offset, nil
}

func decodeTXT(data []byte) (string, error) {
	var value strings.Builder
	for offset := 0; offset < len(data); {
		length := int(data[offset])
		offset++
		if offset+length > len(data) {
			return "", errors.New("truncated TXT character")
		}
		value.Write(data[offset : offset+length])
		offset += length
	}
	return value.String(), nil
}

func decodeRecord(message []byte, offset int) (answer, uint32, int, error) {
	_, next, err := readName(message, offset)
	if err != nil {
		return answer{}, 0, 0, err
	}
	if next+10 > len(message) {
		return answer{}, 0, 0, errors.New("truncated DNS resource record")
	}

	recordType := u16(message[next : next+2])
	ttl := u32(message[next+4 : next+8])
	rdLength := int(u16(message[next+8 : next+10]))
	rdataStart := next + 10
	rdataEnd := rdataStart + rdLength
	if rdataEnd > len(message) {
		return answer{}, 0, 0, errors.New("truncated DNS record data")
	}

	result := answer{ttl: ttl}
	switch recordType {
	case typeA:
		if rdLength != 4 {
			return answer{}, 0, 0, errors.New("A record has an invalid length")
		}
		result.typeName = "A"
		result.value = net.IP(message[rdataStart:rdataEnd]).String()
	case typeAAAA:
		if rdLength != 16 {
			return answer{}, 0, 0, errors.New("AAAA record has an invalid length")
		}
		result.typeName = "AAAA"
		result.value = net.IP(message[rdataStart:rdataEnd]).String()
	case typeCNAME, typeNS:
		name, _, err := readName(message, rdataStart)
		if err != nil {
			return answer{}, 0, 0, err
		}
		result.typeName = typeNames[recordType]
		result.value = name
	case typeMX:
		if rdLength < 3 {
			return answer{}, 0, 0, errors.New("MX record is too short")
		}
		name, _, err := readName(message, rdataStart+2)
		if err != nil {
			return answer{}, 0, 0, err
		}
		result.typeName = "MX"
		result.value = fmt.Sprintf("%d %s", u16(message[rdataStart:rdataStart+2]), name)
	case typeTXT:
		text, err := decodeTXT(message[rdataStart:rdataEnd])
		if err != nil {
			return answer{}, 0, 0, err
		}
		result.typeName = "TXT"
		result.value = text
	}

	return result, ttl, rdataEnd, nil
}

func parseResponse(message []byte, expectedID uint16) (response, error) {
	if len(message) < 12 {
		return response{}, errors.New("DNS response is shorter than its header")
	}
	if u16(message[0:2]) != expectedID {
		return response{}, errors.New("DNS response ID does not match the query")
	}

	questionCount := u16(message[4:6])
	answerCount := u16(message[6:8])
	offset, err := skipQuestions(message, questionCount)
	if err != nil {
		return response{}, err
	}

	result := response{rcode: int(message[3] & 0x0f), recordCount: int(answerCount)}
	for i := 0; i < int(answerCount); i++ {
		record, ttl, next, err := decodeRecord(message, offset)
		if err != nil {
			return response{}, err
		}
		offset = next
		if i == 0 || ttl < result.minTTL {
			result.minTTL = ttl
		}
		if record.typeName != "" {
			result.answers = append(result.answers, record)
		}
	}
	return result, nil
}

func statusName(rcode int) string {
	switch rcode {
	case 0:
		return "NOERROR"
	case 1:
		return "FORMERR"
	case 2:
		return "SERVFAIL"
	case 3:
		return "NXDOMAIN"
	case 5:
		return "REFUSED"
	default:
		return fmt.Sprintf("RCODE%d", rcode)
	}
}

func cacheKey(name, typeName string) string {
	return strings.ToLower(strings.TrimSuffix(name, ".")) + "\x00" + strings.ToUpper(typeName)
}

func exchange(conn *net.UDPConn, name string, qtype, id uint16) (response, bool, error) {
	query, err := buildQuery(id, qtype, name)
	if err != nil {
		return response{}, false, err
	}
	if _, err = conn.Write(query); err != nil {
		return response{}, false, err
	}

	deadline := time.Now().Add(5 * time.Second)
	if err = conn.SetReadDeadline(deadline); err != nil {
		return response{}, false, err
	}
	buffer := make([]byte, 65535)
	for {
		n, err := conn.Read(buffer)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				return response{}, true, nil
			}
			return response{}, false, err
		}
		if n >= 2 && u16(buffer[:2]) != id {
			continue
		}
		parsed, err := parseResponse(buffer[:n], id)
		if err != nil {
			return response{}, false, err
		}
		return parsed, false, nil
	}
}

func printBlock(out *bufio.Writer, queryName, queryType, status string, answers []answer) {
	fmt.Fprintf(out, "query %s %s\n", queryName, queryType)
	fmt.Fprintf(out, "status %s\n", status)
	for _, record := range answers {
		fmt.Fprintf(out, "answer %s %s %d\n", record.typeName, record.value, record.ttl)
	}
	fmt.Fprintln(out, "end")
}

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: run.sh <server-address> <port>")
		os.Exit(1)
	}
	serverIP := net.ParseIP(os.Args[1])
	if serverIP == nil {
		fmt.Fprintln(os.Stderr, "server address must be a numeric IP address")
		os.Exit(1)
	}
	port, err := strconv.Atoi(os.Args[2])
	if err != nil || port < 1 || port > 65535 {
		fmt.Fprintln(os.Stderr, "port must be between 1 and 65535")
		os.Exit(1)
	}

	conn, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: serverIP, Port: port})
	if err != nil {
		fmt.Fprintln(os.Stderr, "cannot create UDP socket:", err)
		os.Exit(1)
	}
	defer conn.Close()

	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()
	cache := make(map[string]cacheEntry)
	var nextID uint16 = 1
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) == 0 {
			continue
		}
		if len(fields) != 2 {
			fmt.Fprintln(os.Stderr, "each query must contain a name and a type")
			os.Exit(1)
		}

		queryName, queryType := fields[0], fields[1]
		normalizedType := strings.ToUpper(queryType)
		qtype, ok := typeCodes[normalizedType]
		if !ok {
			fmt.Fprintln(os.Stderr, "unsupported DNS type:", queryType)
			os.Exit(1)
		}
		key := cacheKey(queryName, normalizedType)
		if entry, ok := cache[key]; ok && time.Now().Before(entry.expires) {
			printBlock(out, queryName, queryType, "NOERROR", entry.answers)
			continue
		}
		delete(cache, key)

		result, timedOut, err := exchange(conn, queryName, qtype, nextID)
		nextID++
		if err != nil {
			fmt.Fprintln(os.Stderr, "DNS error:", err)
			os.Exit(1)
		}
		if timedOut {
			printBlock(out, queryName, queryType, "TIMEOUT", nil)
			out.Flush()
			os.Exit(1)
		}

		printBlock(out, queryName, queryType, statusName(result.rcode), result.answers)
		if result.rcode == 0 && result.recordCount > 0 && result.minTTL > 0 {
			copied := append([]answer(nil), result.answers...)
			cache[key] = cacheEntry{answers: copied, expires: time.Now().Add(time.Duration(result.minTTL) * time.Second)}
		}
	}
	if err := scanner.Err(); err != nil {
		fmt.Fprintln(os.Stderr, "input error:", err)
		os.Exit(1)
	}
}
