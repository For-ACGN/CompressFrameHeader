package cfh

import (
	"bytes"
	"errors"
	"fmt"
	"io"
)

// Reader is used to decompress frame header data.
type Reader struct {
	r    io.Reader
	dict [][]byte
	buf  []byte
	chg  []byte
	data []byte
	last bytes.Buffer
	rem  bytes.Buffer
	err  error
}

// NewReader is used to create a new compressor with 256 dictionaries.
func NewReader(r io.Reader) io.Reader {
	r, err := NewReaderWithSize(r, 256)
	if err != nil {
		panic(err)
	}
	return r
}

// NewReaderWithSize is used to create a new decompressor with custom number of dictionaries.
func NewReaderWithSize(r io.Reader, size int) (io.Reader, error) {
	if size < 1 {
		return nil, errors.New("dictionary size cannot less than 1")
	}
	if size > 256 {
		return nil, errors.New("dictionary size cannot greater than 256")
	}
	return &Reader{
		r:    r,
		dict: make([][]byte, size),
		buf:  make([]byte, 1),
		chg:  make([]byte, 256),
	}, nil
}

// Read is used to decompress frame header data from the under r and copy to b.
func (r *Reader) Read(b []byte) (int, error) {
	l := len(b)
	if l < 1 {
		return 0, nil
	}
	if l > maxDataSize {
		return 0, errors.New("read with too large buffer")
	}
	if r.err != nil {
		return 0, r.err
	}
	n, err := r.read(b)
	if err != nil {
		r.err = err
	}
	return n, err
}

func (r *Reader) read(b []byte) (int, error) {
	// read remaining data
	if r.rem.Len() != 0 {
		return r.rem.Read(b)
	}
	// read command
	_, err := io.ReadFull(r.r, r.buf)
	if err != nil {
		return 0, fmt.Errorf("failed to read decompress command: %s", err)
	}
	switch cmd := r.buf[0]; cmd {
	case cmdAddDict:
		err = r.addDictionary()
	case cmdData:
		err = r.readChangedData()
	case cmdLast:
		r.reuseLastData()
	case cmdPrev:
		err = r.reusePreviousData()
	default:
		return 0, fmt.Errorf("invalid decompress command: %d", cmd)
	}
	if err != nil {
		return 0, err
	}
	n := copy(b, r.data)
	if n < len(r.data) {
		r.rem.Write(r.data[n:])
	}
	return n, nil
}

func (r *Reader) addDictionary() error {
	// read dictionary size
	_, err := io.ReadFull(r.r, r.buf)
	if err != nil {
		return fmt.Errorf("failed to read dictionary size: %s", err)
	}
	size := int(r.buf[0])
	if size < 1 {
		return errors.New("read empty dictionary")
	}
	// read dictionary data
	dict := make([]byte, size)
	_, err = io.ReadFull(r.r, dict)
	if err != nil {
		return fmt.Errorf("failed to read dictionary data: %s", err)
	}
	// remove the oldest dictionary
	for i := len(r.dict) - 1; i > 0; i-- {
		r.dict[i] = r.dict[i-1]
	}
	r.dict[0] = dict
	// update status
	r.data = dict
	r.updateLast(dict)
	return nil
}

func (r *Reader) readChangedData() error {
	// read dictionary index
	_, err := io.ReadFull(r.r, r.buf)
	if err != nil {
		return fmt.Errorf("failed to read dictionary index: %s", err)
	}
	idx := int(r.buf[0])
	dict := r.dict[idx]
	if len(dict) < 1 {
		return fmt.Errorf("read invalid dictionary index: %d", idx)
	}
	// read the number of changed data
	_, err = io.ReadFull(r.r, r.buf)
	if err != nil {
		return fmt.Errorf("failed to read the number of changed data: %s", err)
	}
	// read changed data
	size := int(r.buf[0] * 2)
	if size > len(dict)*2 {
		return fmt.Errorf("read invalid changed data size: %d", size/2)
	}
	_, err = io.ReadFull(r.r, r.chg[:size])
	if err != nil {
		return fmt.Errorf("failed to read changed data: %s", err)
	}
	// extract data and update dictionary
	var dataIdx byte
	maxIdx := byte(len(dict) - 1)
	for i := 0; i < size; i += 2 {
		dataIdx = r.chg[i]
		if dataIdx > maxIdx {
			return fmt.Errorf("invalid changed data index: %d", dataIdx)
		}
		dict[dataIdx] = r.chg[i+1]
	}
	// update status
	r.data = dict
	r.moveDictionary(idx)
	r.updateLast(dict)
	return nil
}

func (r *Reader) reuseLastData() {
	r.data = r.last.Bytes()
}

func (r *Reader) reusePreviousData() error {
	// read dictionary index
	_, err := io.ReadFull(r.r, r.buf)
	if err != nil {
		return fmt.Errorf("failed to read dictionary index: %s", err)
	}
	idx := int(r.buf[0])
	dict := r.dict[idx]
	if len(dict) < 1 {
		return fmt.Errorf("read invalid dictionary index: %d", idx)
	}
	// update status
	r.data = dict
	r.moveDictionary(idx)
	r.updateLast(dict)
	return nil
}

func (r *Reader) moveDictionary(idx int) {
	if idx == 0 {
		return
	}
	dict := r.dict[idx]
	for i := idx; i > 0; i-- {
		r.dict[i] = r.dict[i-1]
	}
	r.dict[0] = dict
}

func (r *Reader) updateLast(data []byte) {
	r.last.Reset()
	r.last.Write(data)
}
