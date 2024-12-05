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
	a.Data = []byte{8, 8, 8, 8} // Example: 8.8.8.8 (Google DNS)

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

func main() {
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
	fmt.Println("DNS server is running on 127.0.0.1:2053")

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
			QDCOUNT: 1,
			ANCOUNT: 1,
			NSCOUNT: 0,
			ARCOUNT: 0,
		}

		fmt.Printf("Transaction ID: %04x\n", transactionID)
		fmt.Printf("Flags Byte 1 (data[2]): %08b\n", buf[2])
		fmt.Printf("Flags Byte 2 (data[3]): %08b\n", buf[3])

		fmt.Printf("Extracted RD: %d\n", ExtractRDCode(buf))

		// Build DNS query and answer
		dnsQuery := BuildDNSQuery("codecrafters.io")
		var answer DNSAnswer
		dnsAnswer := answer.BuildDNSAnswer("codecrafters.io")

		// Construct response
		response := header.ToBytes() // This calls SetHeaderFlags internally
		response = append(response, dnsQuery...)
		response = append(response, dnsAnswer...)

		// Send response
		_, err = udpConn.WriteToUDP(response, source)
		if err != nil {
			fmt.Println("Failed to send response:", err)
		}
	}
}
