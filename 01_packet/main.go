package main

import (
	"bufio"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

func decodeHexDump(r io.Reader) ([]byte, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	var digits strings.Builder
	for _, ch := range data {
		switch ch {
		case ' ', '\n', '\r', '\t', ':':
		default:
			digits.WriteByte(ch)
		}
	}

	if digits.Len() == 0 {
		return nil, errors.New("empty hex dump")
	}
	if digits.Len()%2 != 0 {
		return nil, errors.New("hex dump %2")
	}

	result, err := hex.DecodeString(digits.String())
	if err != nil {
		return nil, fmt.Errorf("invalid hex dump: %w", err)
	}
	return result, nil
}

func u16(b []byte) uint16 {
	return uint16(b[0])<<8 | uint16(b[1])
}

func u32(b []byte) uint32 {
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

func mac(b []byte) string {
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", b[0], b[1], b[2], b[3], b[4], b[5])
}

func ipv4(b []byte) string {
	return fmt.Sprintf("%d.%d.%d.%d", b[0], b[1], b[2], b[3])
}

func validIPv4Checksum(header []byte) bool {
	var sum uint32
	for i := 0; i < len(header); i += 2 {
		sum += uint32(u16(header[i : i+2]))
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return uint16(sum) == 0xffff
}

func emit(w *bufio.Writer, key string, value interface{}) {
	fmt.Fprintf(w, "%s %v\n", key, value)
}

func parse(frame []byte, out *bufio.Writer) error {
	if len(frame) < 14 {
		return errors.New("Ethernet header < 14")
	}

	emit(out, "eth.dst", mac(frame[0:6]))

	emit(out, "eth.src", mac(frame[6:12]))
	etherType := u16(frame[12:14])
	emit(out, "eth.ethertype", fmt.Sprintf("0x%04x", etherType))
	if etherType != 0x0800 {
		return nil
	}

	if len(frame) < 14+20 {
		return errors.New("IPv4 base header")
	}
	ip := frame[14:]
	version := ip[0] >> 4
	ihl := int(ip[0]&0x0f) * 4

	if version != 4 {
		return fmt.Errorf("Version is %d", version)
	}
	if ihl < 20 || len(ip) < ihl {
		return errors.New("invalid header length")
	}

	totalLength := int(u16(ip[2:4]))

	if totalLength < ihl {
		return errors.New("IPv4 total shorter header")
	}
	if len(ip) < totalLength {
		return errors.New("IPv4 packet is truncated")
	}
	ip = ip[:totalLength]

	flagsAndOffset := u16(ip[6:8])
	flags := make([]string, 0, 2)
	if flagsAndOffset&0x4000 != 0 {
		flags = append(flags, "DF")
	}
	if flagsAndOffset&0x2000 != 0 {
		flags = append(flags, "MF")
	}
	flagText := "none"
	if len(flags) > 0 {
		flagText = strings.Join(flags, ",")
	}

	fragmentOffset := int(flagsAndOffset&0x1fff) * 8

	protocol := ip[9]
	emit(out, "ip.version", version)
	emit(out, "ip.ihl_bytes", ihl)
	emit(out, "ip.total_length", totalLength)
	emit(out, "ip.id", fmt.Sprintf("0x%04x", u16(ip[4:6])))
	emit(out, "ip.flags", flagText)
	emit(out, "ip.frag_offset", fragmentOffset)
	emit(out, "ip.ttl", ip[8])
	emit(out, "ip.protocol", protocol)
	emit(out, "ip.src", ipv4(ip[12:16]))
	emit(out, "ip.dst", ipv4(ip[16:20]))
	emit(out, "ip.checksum_valid", validIPv4Checksum(ip[:ihl]))

	payload := ip[ihl:]

	if fragmentOffset != 0 {
		emit(out, "payload.length", len(payload))
		return nil
	}

	switch protocol {
	case 6:
		if len(payload) < 20 {
			return errors.New("TCP base header is truncated")
		}
		dataOffset := int(payload[12]>>4) * 4
		if dataOffset < 20 || dataOffset > len(payload) {
			return errors.New("invalid TCP header length")
		}
		flags := make([]string, 0, 6)
		for _, flag := range []struct {
			mask byte
			name string
		}{
			{0x01, "FIN"}, {0x02, "SYN"}, {0x04, "RST"},
			{0x08, "PSH"}, {0x10, "ACK"}, {0x20, "URG"},
		} {
			if payload[13]&flag.mask != 0 {
				flags = append(flags, flag.name)
			}
		}
		flagText := "none"
		if len(flags) > 0 {
			flagText = strings.Join(flags, ",")
		}
		emit(out, "tcp.src_port", u16(payload[0:2]))
		emit(out, "tcp.dst_port", u16(payload[2:4]))
		emit(out, "tcp.seq", u32(payload[4:8]))
		emit(out, "tcp.ack", u32(payload[8:12]))
		emit(out, "tcp.data_offset_bytes", dataOffset)
		emit(out, "tcp.flags", flagText)
		emit(out, "tcp.window", u16(payload[14:16]))
		emit(out, "payload.length", len(payload)-dataOffset)
	case 17:
		if len(payload) < 8 {
			return errors.New("UDP header is truncated")
		}
		udpLength := int(u16(payload[4:6]))

		if udpLength < 8 {
			return errors.New("UDP length < 8")
		}
		if udpLength != len(payload) {
			return errors.New("UDP length not match IPv4 length")
		}
		emit(out, "udp.src_port", u16(payload[0:2]))
		emit(out, "udp.dst_port", u16(payload[2:4]))
		emit(out, "udp.length", udpLength)
		emit(out, "payload.length", len(payload)-8)
	default:
		emit(out, "payload.length", len(payload))
	}

	return nil
}

func main() {
	frame, err := decodeHexDump(os.Stdin)
	if err == nil {
		out := bufio.NewWriter(os.Stdout)
		err = parse(frame, out)
		if err == nil {
			err = out.Flush()
		}
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
