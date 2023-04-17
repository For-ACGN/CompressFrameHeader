package cfh

import (
	"bytes"
	"errors"
	"fmt"
	"io"
)

// Searcher is used to fast search dictionaries for custom frame header.
// Dict is the Writer inner saved dictionaries.
// If cannot to search the target dictionary, return the index -1.
type Searcher = func(dict [][]byte, header []byte) (index int)

// Writer is used to compress frame header data.
type Writer struct {
	w    io.Writer
	ses  map[int]Searcher
	dict [][]byte
	last bytes.Buffer
	chg  bytes.Buffer
	buf  bytes.Buffer
	err  error
}

// NewWriter is used to create a new compressor with 256 dictionaries.
func NewWriter(w io.Writer) *Writer {
	writer, err := NewWriterWithSize(w, 256)
	if err != nil {
		panic(err)
	}
	return writer
}

// NewWriterWithSize is used to create a new compressor with custom number of dictionaries.
func NewWriterWithSize(w io.Writer, size int) (*Writer, error) {
	if size < 1 {
		return nil, errors.New("dictionary size cannot less than 1")
	}
	if size > 256 {
		return nil, errors.New("dictionary size cannot greater than 256")
	}
	return &Writer{
		w:    w,
		dict: make([][]byte, size),
	}, nil
}

// Write is used to compress frame header data and write to the under w.
func (w *Writer) Write(b []byte) (int, error) {
	l := len(b)
	if l < 1 {
		return 0, nil
	}
	if l > maxDataSize {
		return 0, errors.New("write too large data")
	}
	if w.err != nil {
		return 0, w.err
	}
	n, err := w.write(b)
	if err != nil {
		w.err = err
	}
	return n, err
}

func (w *Writer) write(b []byte) (int, error) {
	n := len(b)
	w.buf.Reset()
	// check data is as same as the last
	if bytes.Equal(w.last.Bytes(), b) {
		w.buf.WriteByte(cmdLast)
		_, err := w.w.Write(w.buf.Bytes())
		if err != nil {
			return 0, err
		}
		return n, nil
	}
	// search the dictionary
	idx := w.searchDictionary(b)
	if idx == -1 {
		w.buf.WriteByte(cmdAddDict)
		w.buf.WriteByte(byte(n))
		w.buf.Write(b)
		_, err := w.w.Write(w.buf.Bytes())
		if err != nil {
			return 0, err
		}
		w.addDictionary(b)
		w.updateLast(b)
		return n, nil
	}
	// compare the new data with the dictionary
	dict := w.dict[idx]
	for i := 0; i < n; i++ {
		if dict[i] == b[i] {
			continue
		}
		w.chg.WriteByte(byte(i))
		w.chg.WriteByte(b[i])
		// update dictionary data
		dict[i] = b[i]
	}
	if w.chg.Len() == 0 {
		w.buf.WriteByte(cmdPrev)
		w.buf.WriteByte(byte(idx))
	} else {
		w.buf.WriteByte(cmdData)
		w.buf.WriteByte(byte(idx))
		w.buf.WriteByte(byte(w.chg.Len() / 2))
		w.buf.Write(w.chg.Bytes())
		w.chg.Reset()
	}
	// write the actual changed data
	_, err := w.w.Write(w.buf.Bytes())
	if err != nil {
		return 0, err
	}
	// move the dictionary to the top
	w.moveDictionary(idx)
	w.updateLast(b)
	return n, nil
}

func (w *Writer) searchDictionary(data []byte) int {
	size := len(data)
	if w.ses != nil {
		if searcher, ok := w.ses[size]; ok {
			return searcher(w.dict, data)
		}
	}
	switch {
	case size == ethernetIPv4TCPSize:
		return w.fastSearchDictEthernetIPv4TCP(data)
	case size == ethernetIPv4UDPSize:
		return w.fastSearchDictEthernetIPv4UDP(data)
	case size == ethernetIPv6TCPSize:
		return w.fastSearchDictEthernetIPv6TCP(data)
	case size == ethernetIPv6UDPSize:
		return w.fastSearchDictEthernetIPv6UDP(data)
	default:
		return w.slowSearchDict(data)
	}
}

func (w *Writer) fastSearchDictEthernetIPv4TCP(header []byte) int {
	const offset = 14 + (20 - 4*2)
	var dict []byte
	headerP1 := header[:6+6]
	headerP2 := header[offset : offset+4+4+2+2]
	for i := 0; i < len(w.dict); i++ {
		dict = w.dict[i]
		if len(dict) != len(header) {
			continue
		}
		// Ethernet dst/src address
		if !bytes.Equal(dict[:6+6], headerP1) {
			continue
		}
		// IPv4 src/dst address, TCP/UDP src/dst port
		if !bytes.Equal(dict[offset:offset+4+4+2+2], headerP2) {
			continue
		}
		return i
	}
	return -1
}

func (w *Writer) fastSearchDictEthernetIPv4UDP(header []byte) int {
	const offset = 14 + (20 - 4*2)
	var dict []byte
	headerP1 := header[:6+6]
	headerP2 := header[offset : offset+4+4+2+2]
	for i := 0; i < len(w.dict); i++ {
		dict = w.dict[i]
		if len(dict) != len(header) {
			continue
		}
		// Ethernet dst/src address
		if !bytes.Equal(dict[:6+6], headerP1) {
			continue
		}
		// IPv4 src/dst address, UDP src/dst port
		if !bytes.Equal(dict[offset:offset+4+4+2+2], headerP2) {
			continue
		}
		return i
	}
	return -1
}

func (w *Writer) fastSearchDictEthernetIPv6TCP(header []byte) int {
	const offset = 14 + (40 - 16*2)
	var dict []byte
	headerP1 := header[:6+6]
	headerP2 := header[offset : offset+16+16+2+2]
	for i := 0; i < len(w.dict); i++ {
		dict = w.dict[i]
		if len(dict) != len(header) {
			continue
		}
		// Ethernet dst/src address
		if !bytes.Equal(dict[:6+6], headerP1) {
			continue
		}
		// IPv6 src/dst address, TCP/UDP src/dst port
		if !bytes.Equal(dict[offset:offset+16+16+2+2], headerP2) {
			continue
		}
		return i
	}
	return -1
}

func (w *Writer) fastSearchDictEthernetIPv6UDP(header []byte) int {
	const offset = 14 + (40 - 16*2)
	var dict []byte
	headerP1 := header[:6+6]
	headerP2 := header[offset : offset+16+16+2+2]
	for i := 0; i < len(w.dict); i++ {
		dict = w.dict[i]
		if len(dict) != len(header) {
			continue
		}
		// Ethernet dst/src address
		if !bytes.Equal(dict[:6+6], headerP1) {
			continue
		}
		// IPv6 src/dst address, UDP src/dst port
		if !bytes.Equal(dict[offset:offset+16+16+2+2], headerP2) {
			continue
		}
		return i
	}
	return -1
}

func (w *Writer) slowSearchDict(data []byte) int {
	var (
		dict []byte
		diff int
	)
	minDiff := len(data) / minDiffDiv
	maxDiff := len(data) / maxDiffDiv
	curDiff := maxDataSize
	dictIdx := -1
next:
	for i := 0; i < len(w.dict); i++ {
		dict = w.dict[i]
		if len(dict) != len(data) {
			continue
		}
		// compare difference
		diff = 0
		for j := 0; j < len(dict); j++ {
			if dict[j] == data[j] {
				continue
			}
			diff++
			// if change a lot, skip current dictionary
			if diff > maxDiff {
				continue next
			}
		}
		// if change a little, select current dictionary
		if diff <= minDiff {
			return i
		}
		// update current minimum difference
		if diff < curDiff {
			curDiff = diff
			dictIdx = i
		}
	}
	return dictIdx
}

func (w *Writer) addDictionary(data []byte) {
	// remove the oldest dictionary
	for i := len(w.dict) - 1; i > 0; i-- {
		w.dict[i] = w.dict[i-1]
	}
	dict := make([]byte, len(data))
	copy(dict, data)
	w.dict[0] = dict
}

func (w *Writer) moveDictionary(idx int) {
	if idx == 0 {
		return
	}
	dict := w.dict[idx]
	for i := idx; i > 0; i-- {
		w.dict[i] = w.dict[i-1]
	}
	w.dict[0] = dict
}

func (w *Writer) updateLast(data []byte) {
	w.last.Reset()
	w.last.Write(data)
}

// RegisterSearcher is used to register custom searcher
// for fast search dictionaries with custom frame header.
// Size is the target frame header size.
func (w *Writer) RegisterSearcher(size int, searcher Searcher) error {
	if w.ses == nil {
		w.ses = make(map[int]Searcher, 1)
	}
	if _, ok := w.ses[size]; ok {
		return fmt.Errorf("searcher with size %d is already registered", size)
	}
	w.ses[size] = searcher
	return nil
}
