package main

import (
	"encoding/binary"
	"fmt"
	"net"
)

// Ensures gofmt doesn't remove the "net" import in stage 1 (feel free to remove this!)
var _ = net.ListenUDP

type DNSHeader struct {
	ID      uint16
	Flags   uint16
	QDCOUNT uint16
	ANCOUNT uint16
	NSCOUNT uint16
	ARCOUNT uint16
}

const DNSHeaderSize = 12

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
		h.Flags = 1 << 7
		h.QDCOUNT = 0
		h.ANCOUNT = 0
		h.NSCOUNT = 0
		h.ARCOUNT = 0

		response := h.ToBytes()

		// binary.BigEndian.PutUint16(response[0:2], 1234)
		response[2] = 1 << 7

		_, err = udpConn.WriteToUDP(response, source)

		if err != nil {
			fmt.Println("Failed to send response:", err)
		}
	}
}
