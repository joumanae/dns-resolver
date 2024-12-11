package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"net"
)

// Ensures gofmt doesn't remove the "net" import in stage 1 (feel free to remove this!)
var _ = net.ListenUDP

const (
	TYPE_A   = 1
	CLASS_IN = 1
)

type DNSPacket struct {
	Header   DNSHeader
	Question DNSQuestion
	Answer   DNSAnswer
}

type DNSHeader struct {
	ID      uint16
	Flags   Flags
	QDCOUNT uint16
	ANCOUNT uint16
	NSCOUNT uint16
	ARCOUNT uint16
}

const DNSHeaderSize = 12

type DNSQuestion struct {
	Name  []byte
	Type  uint16
	Class uint16
}

type DNSAnswer struct {
	Name   []byte
	Type   uint16
	Class  uint16
	TTL    uint32
	Length uint16
	Data   []byte
}

type Flags struct {
	QRIndicator uint16
	Opcode      uint16
	AA          uint16
	TC          uint16
	RD          uint16
	RA          uint16
	Z           uint16
	RCode       uint16
}

const AABitMask uint16 = 0x0400 // Bit 5 corresponds to AA

func (f Flags) SetHeaderFlagsToUint16() uint16 {
	var flags uint16
	flags |= (f.QRIndicator << 15)
	flags |= (f.Opcode << 11)
	flags |= (f.AA << 10)
	flags |= (f.TC << 9)
	flags |= (f.RD << 8)
	flags |= (f.RA << 7)
	flags |= (f.Z << 4)
	flags |= (f.RCode)
	return flags
}

func (h DNSHeader) ToBytes() []byte {
	headerSlice := make([]byte, DNSHeaderSize)
	binary.BigEndian.PutUint16(headerSlice[0:2], h.ID)
	binary.BigEndian.PutUint16(headerSlice[2:4], h.Flags.SetHeaderFlagsToUint16())
	binary.BigEndian.PutUint16(headerSlice[4:6], h.QDCOUNT)
	binary.BigEndian.PutUint16(headerSlice[6:8], h.ANCOUNT)
	binary.BigEndian.PutUint16(headerSlice[8:10], h.NSCOUNT)
	binary.BigEndian.PutUint16(headerSlice[10:12], h.ARCOUNT)
	return headerSlice
}

func (q DNSAnswer) ToBytes() []byte {
	var dnsAnswer []byte
	dnsAnswer = append(dnsAnswer, EncodeDnsName(string(q.Name))...)
	dnsAnswer = binary.BigEndian.AppendUint16(dnsAnswer, q.Type)
	dnsAnswer = binary.BigEndian.AppendUint16(dnsAnswer, q.Class)
	dnsAnswer = binary.BigEndian.AppendUint32(dnsAnswer, q.TTL)
	dnsAnswer = binary.BigEndian.AppendUint16(dnsAnswer, q.Length)
	dnsAnswer = append(dnsAnswer, q.Data...) // Append raw IP data
	return dnsAnswer
}

func EncodeDnsName(domainName string) []byte {
	var encodedDomain []byte
	parts := bytes.Split([]byte(domainName), []byte("."))
	for _, part := range parts {
		encodedDomain = append(encodedDomain, byte(len(part)))
		encodedDomain = append(encodedDomain, part...)
	}
	encodedDomain = append(encodedDomain, 0x00)
	return encodedDomain
}

func BuildDNSQuery(domainName string) []byte {
	var dnsQuery []byte
	dnsQuery = append(dnsQuery, EncodeDnsName(domainName)...)
	dnsQuery = binary.BigEndian.AppendUint16(dnsQuery, TYPE_A)
	dnsQuery = binary.BigEndian.AppendUint16(dnsQuery, CLASS_IN)
	return dnsQuery
}

func (a DNSAnswer) BuildDNSAnswer(domainName, ipAddress string) []byte {
	var dnsAnswer []byte
	a.Type = TYPE_A
	a.Class = CLASS_IN
	a.TTL = 60
	a.Length = 4
	a.Data = []byte(ipAddress)

	dnsAnswer = append(dnsAnswer, EncodeDnsName(domainName)...)
	dnsAnswer = binary.BigEndian.AppendUint16(dnsAnswer, a.Type)
	dnsAnswer = binary.BigEndian.AppendUint16(dnsAnswer, a.Class)
	dnsAnswer = binary.BigEndian.AppendUint32(dnsAnswer, a.TTL)
	dnsAnswer = binary.BigEndian.AppendUint16(dnsAnswer, a.Length)
	dnsAnswer = append(dnsAnswer, a.Data...) // Append raw IP data
	return dnsAnswer
}

func ExtractRDCode(buf []byte) uint16 {
	flags := binary.BigEndian.Uint16(buf[2:4])
	return (flags >> 8) & 0x1
}

func UnmarshalQuestions(buf []byte, count uint16) ([]DNSQuestion, int) {
	var questions []DNSQuestion
	offset := 12 // Start of the question section
	for i := 0; i < int(count); i++ {
		name, consumed := DecodeDNSName(buf[offset:])
		offset += consumed
		question := DNSQuestion{
			Name:  name,
			Type:  binary.BigEndian.Uint16(buf[offset : offset+2]),
			Class: binary.BigEndian.Uint16(buf[offset+2 : offset+4]),
		}
		offset += 4 // Move past Type and Class
		questions = append(questions, question)
	}
	return questions, offset
}

func DecodeDNSName(data []byte) ([]byte, int) {
	var name []byte
	offset := 0
	for {
		length := int(data[offset])
		if length == 0 {
			offset++ // End of name
			break
		}
		offset++
		name = append(name, data[offset:offset+length]...)
		name = append(name, '.')
		offset += length
	}
	return name[:len(name)-1], offset // Remove trailing dot
}

func BuildMultipleDNSAnswers(questions []DNSQuestion, ipAddress string) []DNSAnswer {
	var answers []DNSAnswer

	// Strip port if present
	host, _, err := net.SplitHostPort(ipAddress)
	if err != nil {
		// If no port is present, assume ipAddress is just the IP
		host = ipAddress
	}

	// Parse and validate IPv4 address
	parsedIP := net.ParseIP(host).To4()
	if parsedIP == nil {
		fmt.Printf("Invalid IPv4 address: %s\n", host)
		return nil // Handle invalid IP case
	}

	// Build answers
	for _, question := range questions {
		answers = append(answers, DNSAnswer{
			Name:   question.Name,
			Type:   TYPE_A,
			Class:  CLASS_IN,
			TTL:    60,
			Length: uint16(len(parsedIP)), // Should be 4 for IPv4
			Data:   parsedIP,
		})
	}
	return answers
}

// Forward the DNS query to the resolver and return the response.
func ForwardQuery(query []byte, resolver string) ([]byte, error) {
	serverAddr, err := net.ResolveUDPAddr("udp", resolver)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve resolver address: %w", err)
	}

	fmt.Printf("Forwarding to resolver: %s\n", serverAddr.String())

	conn, err := net.DialUDP("udp", nil, serverAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to resolver: %w", err)
	}
	defer conn.Close()

	_, err = conn.Write(query)
	if err != nil {
		return nil, fmt.Errorf("failed to send query: %w", err)
	}

	response := make([]byte, 512)
	size, err := conn.Read(response)
	if err != nil {
		return nil, fmt.Errorf("failed to receive response: %w", err)
	}

	return response[:size], nil
}

func main() {
	// add the flag --resolver <address>
	resolverAddress := flag.String("resolver", "", "DNS resolver address")
	flag.Parse()
	udpAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:2053")
	if err != nil {
		fmt.Println("Failed to resolve UDP address:", err)
		return
	}

	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		fmt.Println("Failed to bind to address:", err)
		return
	}
	defer udpConn.Close()

	buf := make([]byte, 512)

	for {
		size, source, err := udpConn.ReadFromUDP(buf)
		if err != nil {
			fmt.Println("Error receiving data:", err)
			continue
		}

		fmt.Printf("Received %d bytes from %s\n", size, source)

		// Extract transaction ID and flags from the query
		transactionID := binary.BigEndian.Uint16(buf[:2])
		qdCount := binary.BigEndian.Uint16(buf[4:6])
		questions, offset := UnmarshalQuestions(buf, qdCount)
		answers := BuildMultipleDNSAnswers(questions, *resolverAddress)

		// Prepare DNS header with flags
		flags := binary.BigEndian.Uint16(buf[2:4])
		opcode := (flags >> 11) & 0xF
		rcode := flags & 0xF
		if opcode != 0 {
			rcode = 4
		}

		header := DNSHeader{
			ID: transactionID,
			Flags: Flags{
				QRIndicator: 1, // Response
				Opcode:      opcode,
				AA:          0, // Not authoritative
				TC:          0, // Not truncated
				RD:          ExtractRDCode(buf),
				RA:          1, // Recursion not available
				Z:           0, // Reserved
				RCode:       rcode,
			},
			QDCOUNT: uint16(len(questions)), // Match the number of questions
			ANCOUNT: uint16(len(answers)),
			NSCOUNT: 0,
			ARCOUNT: 0,
		}

		DNSmessage := header.ToBytes()
		DNSmessage = append(DNSmessage, buf[12:offset]...)

		for _, answer := range answers {
			DNSmessage = append(DNSmessage, answer.ToBytes()...)
		}

		response, err := ForwardQuery(buf[:size], *resolverAddress)
		if err != nil {
			fmt.Println("Error forwarding query to resolver:", err)
			continue
		}
		DNSmessage = append(DNSmessage, response...)
		// Send the resolver's response back to the client.
		_, err = udpConn.WriteToUDP(DNSmessage, source)
		if err != nil {
			fmt.Println("Failed to send response to client:", err)
		}

	}
}
