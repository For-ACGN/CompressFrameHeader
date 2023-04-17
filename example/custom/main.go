package main

import (
	"bytes"
	"log"

	"github.com/For-ACGN/CompressFrameHeader"
)

func main() {
	const headerSize = 16 + 16

	// build fake ethernet frame
	customFrame := make([]byte, 16+16+100)
	customFrame[0] = 0x01
	customFrame[16] = 0x02
	copy(customFrame[headerSize:], bytes.Repeat([]byte{1}, 100))

	searcher := func(dict [][]byte, header []byte) (index int) {
		var d []byte
		for i := 0; i < len(dict); i++ {
			d = dict[i]
			if len(d) != len(header) {
				continue
			}
			// source GUID
			if !bytes.Equal(d[:16], header[:16]) {
				continue
			}
			// destination GUID
			if !bytes.Equal(d[16:32], header[16:32]) {
				continue
			}
			return i
		}
		return -1
	}

	// compress frame header
	buf := bytes.NewBuffer(nil)
	buf.Grow(cfh.MaxFrameHeaderSize)
	w := cfh.NewWriter(buf)
	err := w.RegisterSearcher(32, searcher)
	checkError(err)
	n, err := w.Write(customFrame[:headerSize])
	checkError(err)
	if n != headerSize {
		log.Fatal("invalid n")
	}

	// encode frame
	payloadSize := byte(len(customFrame) - headerSize)
	output := bytes.NewBuffer(make([]byte, 0, 4096))
	output.WriteByte(byte(headerSize))     // compressed frame header size
	output.Write(buf.Bytes())              // compressed frame header
	output.WriteByte(payloadSize)          // payload size
	output.Write(customFrame[headerSize:]) // payload

	// read compressed frame header size
	cs, err := output.ReadByte()
	checkError(err)
	// read compressed frame header
	buffer := make([]byte, cfh.MaxFrameHeaderSize)
	r := cfh.NewReader(output)
	n, err = r.Read(buffer[:cs])
	checkError(err)
	if !bytes.Equal(customFrame[:headerSize], buffer[:n]) {
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
