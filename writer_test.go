package cfh

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"sync"
	"testing"

	"github.com/agiledragon/gomonkey/v2"
	"github.com/stretchr/testify/require"
)

func TestNewWriter(t *testing.T) {
	t.Run("common", func(t *testing.T) {
		output := bytes.NewBuffer(make([]byte, 0, 64))

		w := NewWriter(output)
		require.NotNil(t, w)
	})

	t.Run("too small dictionary size", func(t *testing.T) {
		output := bytes.NewBuffer(make([]byte, 0, 64))

		w, err := NewWriterWithSize(output, 0)
		require.EqualError(t, err, "dictionary size cannot less than 1")
		require.Nil(t, w)
	})

	t.Run("too large dictionary size", func(t *testing.T) {
		output := bytes.NewBuffer(make([]byte, 0, 64))

		w, err := NewWriterWithSize(output, 4096)
		require.EqualError(t, err, "dictionary size cannot greater than 256")
		require.Nil(t, w)
	})

	t.Run("panic with default parameters", func(t *testing.T) {
		outputs := []interface{}{nil, errors.New("monkey error")}
		patch := gomonkey.ApplyFuncReturn(NewWriterWithSize, outputs...)
		defer patch.Reset()

		output := bytes.NewBuffer(make([]byte, 0, 64))

		defer func() {
			r := recover()
			require.NotNil(t, r)
		}()
		_ = NewWriter(output)
	})
}

func TestWriter_Write(t *testing.T) {
	output := bytes.NewBuffer(make([]byte, 0, 4096))

	t.Run("write as same as the last", func(t *testing.T) {
		w := NewWriter(output)
		for i := 0; i < 100; i++ {
			n, err := w.Write(testIPv4TCPFrameHeader1)
			require.NoError(t, err)
			require.Equal(t, len(testIPv4TCPFrameHeader1), n)
		}

		r := NewReader(output)
		buf := make([]byte, len(testIPv4TCPFrameHeader1))
		for i := 0; i < 100; i++ {
			n, err := r.Read(buf)
			require.NoError(t, err)
			require.Equal(t, len(testIPv4TCPFrameHeader1), n)
			require.Equal(t, testIPv4TCPFrameHeader1, buf)
		}
	})

	t.Run("write as same as the previous", func(t *testing.T) {
		w := NewWriter(output)

		n, err := w.Write(testIPv4TCPFrameHeader1)
		require.NoError(t, err)
		require.Equal(t, len(testIPv4TCPFrameHeader1), n)

		n, err = w.Write(testIPv4TCPFrameHeader2)
		require.NoError(t, err)
		require.Equal(t, len(testIPv4TCPFrameHeader2), n)

		n, err = w.Write(testIPv4TCPFrameHeader1)
		require.NoError(t, err)
		require.Equal(t, len(testIPv4TCPFrameHeader1), n)

		r := NewReader(output)

		buf := make([]byte, len(testIPv4TCPFrameHeader1))
		n, err = r.Read(buf)
		require.NoError(t, err)
		require.Equal(t, len(testIPv4TCPFrameHeader1), n)
		require.Equal(t, testIPv4TCPFrameHeader1, buf)

		buf = make([]byte, len(testIPv4TCPFrameHeader2))
		n, err = r.Read(buf)
		require.NoError(t, err)
		require.Equal(t, len(testIPv4TCPFrameHeader2), n)
		require.Equal(t, testIPv4TCPFrameHeader2, buf)

		buf = make([]byte, len(testIPv4TCPFrameHeader1))
		n, err = r.Read(buf)
		require.NoError(t, err)
		require.Equal(t, len(testIPv4TCPFrameHeader1), n)
		require.Equal(t, testIPv4TCPFrameHeader1, buf)
	})

	t.Run("write empty data", func(t *testing.T) {
		w := NewWriter(output)

		n, err := w.Write(nil)
		require.NoError(t, err)
		require.Zero(t, n)
	})

	t.Run("write too large data", func(t *testing.T) {
		w := NewWriter(output)

		data := bytes.Repeat([]byte{0}, maxDataSize+1)
		n, err := w.Write(data)
		require.EqualError(t, err, "write too large data")
		require.Zero(t, n)
	})

	t.Run("write after appear error", func(t *testing.T) {
		pr, pw := io.Pipe()
		err := pr.Close()
		require.NoError(t, err)

		w := NewWriter(pw)

		n, err := w.Write(testIPv4TCPFrameHeader1)
		require.Equal(t, io.ErrClosedPipe, err)
		require.Zero(t, n)

		n, err = w.Write(testIPv4TCPFrameHeader1)
		require.Equal(t, io.ErrClosedPipe, err)
		require.Zero(t, n)

		err = pw.Close()
		require.NoError(t, err)
	})

	t.Run("failed to write last", func(t *testing.T) {
		pr, pw := io.Pipe()
		wg := sync.WaitGroup{}
		wg.Add(1)
		go func() {
			defer wg.Done()
			buf := make([]byte, 1024)
			_, err := pr.Read(buf)
			require.NoError(t, err)
		}()

		w := NewWriter(pw)

		n, err := w.Write(testIPv4TCPFrameHeader1)
		require.NoError(t, err)
		require.Equal(t, len(testIPv4TCPFrameHeader1), n)

		wg.Wait()

		err = pr.Close()
		require.NoError(t, err)

		n, err = w.Write(testIPv4TCPFrameHeader1)
		require.Equal(t, io.ErrClosedPipe, err)
		require.Zero(t, n)

		err = pw.Close()
		require.NoError(t, err)
	})

	t.Run("failed to write changed data", func(t *testing.T) {
		pr, pw := io.Pipe()
		wg := sync.WaitGroup{}
		wg.Add(1)
		go func() {
			defer wg.Done()
			buf := make([]byte, 1024)
			_, err := pr.Read(buf)
			require.NoError(t, err)
			_, err = pr.Read(buf)
			require.NoError(t, err)
		}()

		w := NewWriter(pw)

		n, err := w.Write(testIPv4TCPFrameHeader1)
		require.NoError(t, err)
		require.Equal(t, len(testIPv4TCPFrameHeader1), n)

		n, err = w.Write(testIPv4TCPFrameHeader2)
		require.NoError(t, err)
		require.Equal(t, len(testIPv4TCPFrameHeader2), n)

		wg.Wait()

		err = pr.Close()
		require.NoError(t, err)

		n, err = w.Write(testIPv4TCPFrameHeader1)
		require.Equal(t, io.ErrClosedPipe, err)
		require.Zero(t, n)

		err = pw.Close()
		require.NoError(t, err)
	})
}

func TestWriter_searchDictionary(t *testing.T) {
	t.Run("fast", func(t *testing.T) {
		output := bytes.NewBuffer(make([]byte, 0, 4096))

		w := NewWriter(output)
		for _, header := range testFrameHeaders {
			n, err := w.Write(header)
			require.NoError(t, err)
			require.Equal(t, len(header), n)
		}

		r := NewReader(output)
		for _, header := range testFrameHeaders {
			buf := make([]byte, len(header))
			n, err := r.Read(buf)
			require.NoError(t, err)
			require.Equal(t, len(header), n)
			require.Equal(t, header, buf)
		}
	})

	t.Run("slow", func(t *testing.T) {
		output := bytes.NewBuffer(make([]byte, 0, 4096))

		headers := testFrameHeaders
		for i := 0; i < 16; i++ {
			noise := make([]byte, 64)
			_, err := rand.Read(noise)
			require.NoError(t, err)
			headers = append(headers, noise)
		}

		// append similar frame headers
		header := make([]byte, 64)
		_, err := rand.Read(header)
		require.NoError(t, err)
		sHeader1 := make([]byte, 64)
		copy(sHeader1, header)
		for i := 0; i < len(header)/minDiffDiv+2; i++ {
			sHeader1[i+10]++
		}
		sHeader2 := make([]byte, 64)
		copy(sHeader2, header)
		for i := 0; i < len(header)/minDiffDiv+3; i++ {
			sHeader2[i+10]++
		}
		headers = append(headers, header, sHeader1, sHeader2)

		w := NewWriter(output)
		for _, h := range headers {
			nh := append(h, 0)
			n, err := w.Write(nh)
			require.NoError(t, err)
			require.Equal(t, len(nh), n)
		}

		r := NewReader(output)
		for _, h := range headers {
			nh := append(h, 0)
			buf := make([]byte, len(nh))
			n, err := r.Read(buf)
			require.NoError(t, err)
			require.Equal(t, len(nh), n)
			require.Equal(t, nh, buf)
		}
	})
}
