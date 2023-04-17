package main

import (
	"bytes"
	"log"

	"github.com/For-ACGN/CompressFrameHeader"
)

func main() {
	// build fake ethernet frame
	ethIPv4TCP := make([]byte, 14+20+20+100)
	ethIPv4TCP[12] = 0x08 // Protocol(IPv4)
	ethIPv4TCP[13] = 0x00 // Protocol(IPv4)
	ethIPv4TCP[14] = 0x45 // IPv4 version
	ethIPv4TCP[23] = 0x06 // TCP
	ethIPv4TCP[46] = 0x50 // TCP header length
	copy(ethIPv4TCP[54:], bytes.Repeat([]byte{1}, 100))

	// check frame header
	size, prefer := cfh.IsFrameHeaderPreferBeCompressed(ethIPv4TCP)
	if !prefer {
		log.Fatal("invalid ethernet frame")
	}
	// compress frame header
	buf := bytes.NewBuffer(make([]byte, 0, 256))
	w := cfh.NewWriter(buf)
	n, err := w.Write(ethIPv4TCP[:size])
	checkError(err)
	if n != len(ethIPv4TCP[:size]) {
		log.Fatal("invalid n")
	}

	// encode frame
	payloadSize := byte(len(ethIPv4TCP) - size)
	output := bytes.NewBuffer(make([]byte, 0, 4096))
	output.WriteByte(byte(size))  // compressed frame header size
	output.Write(buf.Bytes())     // compressed frame header
	output.WriteByte(payloadSize) // payload size
	output.Write(ethIPv4TCP[54:]) // payload

	// read compressed frame header size
	cs, err := output.ReadByte()
	checkError(err)
	// read compressed frame header
	buffer := make([]byte, cfh.MaxFrameHeaderSize)
	r := cfh.NewReader(output)
	n, err = r.Read(buffer[:cs])
	checkError(err)
	if !bytes.Equal(ethIPv4TCP[:54], buffer[:n]) {
		log.Fatal("invalid frame header")
	}
	// read payload size
	ps, err := output.ReadByte()
	checkError(err)
	// read payload
	payload := make([]byte, ps)
	n, err = output.Read(payload)
	checkError(err)
	if !bytes.Equal(bytes.Repeat([]byte{1}, 100), payload[:n]) {
		log.Fatal("invalid payload data")
	}
}

func checkError(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
