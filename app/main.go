package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
)

// Ensures gofmt doesn't remove the "net" import in stage 1 (feel free to remove this!)
var _ = net.ListenUDP

const (
	TYPE_A   = 1
	CLASS_IN = 1
)

type DNSHeader struct {
	ID      uint16
	Flags   uint16
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

func (h DNSHeader) ToBytes() []byte {
	headerSlice := make([]byte, DNSHeaderSize)

	// BigEndian saves the most significant piece of data at the lowest in memory
	// Endian is useful when data isn't single-byte. In our case, each element is multiple bytes
	binary.BigEndian.PutUint16(headerSlice[0:2], 1234)
	binary.BigEndian.PutUint16(headerSlice[2:4], h.Flags)
	binary.BigEndian.PutUint16(headerSlice[4:6], h.QDCOUNT)
	binary.BigEndian.PutUint16(headerSlice[6:8], h.ANCOUNT)
	binary.BigEndian.PutUint16(headerSlice[8:10], h.NSCOUNT)
	binary.BigEndian.PutUint16(headerSlice[10:12], h.ARCOUNT)
	return headerSlice
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

func (a DNSAnswer) BuildDNSAnswer(domainName string) []byte {
	var dnsAnswer []byte
	a.Type = TYPE_A
	a.Class = CLASS_IN
	a.TTL = 60
	a.Length = 4
	a.Data = []byte("\x08\x08\x08\x08")

	dnsAnswer = append(dnsAnswer, EncodeDnsName(domainName)...)
	dnsAnswer = binary.BigEndian.AppendUint16(dnsAnswer, a.Type)
	dnsAnswer = binary.BigEndian.AppendUint16(dnsAnswer, a.Class)
	dnsAnswer = binary.BigEndian.AppendUint32(dnsAnswer, a.TTL)
	dnsAnswer = binary.BigEndian.AppendUint16(dnsAnswer, a.Length)
	dnsAnswer = binary.BigEndian.AppendUint32(dnsAnswer, binary.BigEndian.Uint32(a.Data))
	return dnsAnswer
}

func main() {
	// You can use print statements as follows for debugging, they'll be visible when running tests.
	fmt.Println("Logs from your program will appear here!")

	// Uncomment this block to pass the first stage
	//
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
			break
		}

		receivedData := string(buf[:size])
		fmt.Printf("Received %d bytes from %s: %s\n", size, source, receivedData)

		// Create an empty response

		var h DNSHeader
		h.ID = 1234
		h.Flags = 0x8000
		h.QDCOUNT = 1
		h.ANCOUNT = 1
		h.NSCOUNT = 0x0000
		h.ARCOUNT = 0x0000

		dnsQuery := BuildDNSQuery("codecrafters.io")

		var a DNSAnswer

		dnsAnswer := a.BuildDNSAnswer("codecrafters.io")

		response := h.ToBytes()

		response = append(response, dnsQuery...)
		response = append(response, dnsAnswer...)
		// Write the response

		_, err = udpConn.WriteToUDP(response, source)

		if err != nil {
			fmt.Println("Failed to send response:", err)
		}
	}
}
