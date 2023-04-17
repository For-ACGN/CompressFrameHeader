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

func TestWriter_RegisterSearcher(t *testing.T) {
	t.Run("common", func(t *testing.T) {
		output := bytes.NewBuffer(make([]byte, 0, 4096))

		w := NewWriter(output)

		searcher := func(dict [][]byte, header []byte) int {
			var d []byte
			for i := 0; i < len(dict); i++ {
				d = dict[i]
				if len(d) != len(header) {
					continue
				}
				// src/dst GUID
				if !bytes.Equal(d[:32], header[:32]) {
					continue
				}
				return i
			}
			return -1
		}
		err := w.RegisterSearcher(64, searcher)
		require.NoError(t, err)

		frameHeaders := [][]byte{
			bytes.Repeat([]byte{0}, 64),
			bytes.Repeat([]byte{0}, 64),
			bytes.Repeat([]byte{0}, 64),
			bytes.Repeat([]byte{1}, 64),
			bytes.Repeat([]byte{1}, 64),
			bytes.Repeat([]byte{1}, 64),
			bytes.Repeat([]byte{0}, 64),
			bytes.Repeat([]byte{0}, 64),
			bytes.Repeat([]byte{0}, 64),
		}

		for _, header := range frameHeaders {
			n, err := w.Write(header)
			require.NoError(t, err)
			require.Equal(t, len(header), n)
		}

		r := NewReader(output)
		for _, header := range frameHeaders {
			buf := make([]byte, len(header))
			n, err := r.Read(buf)
			require.NoError(t, err)
			require.Equal(t, len(header), n)
			require.Equal(t, header, buf)
		}
	})

	t.Run("already registered", func(t *testing.T) {
		output := bytes.NewBuffer(make([]byte, 0, 4096))

		w := NewWriter(output)

		searcher := func(dict [][]byte, header []byte) int {
			return -1
		}

		err := w.RegisterSearcher(64, searcher)
		require.NoError(t, err)
		err = w.RegisterSearcher(64, searcher)
		require.EqualError(t, err, "searcher with size 64 is already registered")

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
}

func TestWriter_Fuzz(t *testing.T) {
	output := bytes.NewBuffer(make([]byte, 0, 4*1024*1024))
	headers := testGenerateFrameHeaders(t)

	w := NewWriter(output)
	for _, header := range headers {
		n, err := w.Write(header)
		require.NoError(t, err)
		require.Equal(t, len(header), n)
	}

	r := NewReader(output)
	for _, header := range headers {
		buf := make([]byte, len(header))
		n, err := r.Read(buf)
		require.NoError(t, err)
		require.Equal(t, len(header), n)
		require.Equal(t, header, buf)
	}
}

func BenchmarkWriter_Write(b *testing.B) {
	b.Run("Ethernet IPv4 TCP", benchmarkWriterWriteEthernetIPv4TCP)
	b.Run("Ethernet IPv4 UDP", benchmarkWriterWriteEthernetIPv4UDP)
	b.Run("Ethernet IPv6 TCP", benchmarkWriterWriteEthernetIPv6TCP)
	b.Run("Ethernet IPv6 UDP", benchmarkWriterWriteEthernetIPv6UDP)
	b.Run("Custom Frame Header", benchmarkWriterWriteCustomFrameHeader)
}

func benchmarkWriterWriteEthernetIPv4TCP(b *testing.B) {
	b.Run("single dictionary", func(b *testing.B) {
		output := bytes.NewBuffer(make([]byte, 0, 64*1024*1024))
		w := NewWriter(output)

		header := make([]byte, len(testIPv4TCPFrameHeader1))
		copy(header, testIPv4TCPFrameHeader1)

		b.ReportAllocs()
		b.ResetTimer()

		var err error
		for i := 0; i < b.N; i++ {
			_, err = w.Write(header)
			if err != nil {
				b.Fatal(err)
			}

			// data that change frequently
			header[17] = byte(i) + 1 // IPv4 Total Length [byte 2]
			header[19] = byte(i) + 2 // IPv4 ID [byte 2]
			header[25] = byte(i) + 3 // IPv4 checksum [byte 2]

			header[41] = byte(i) + 4 // TCP Sequence [byte 4]
			header[45] = byte(i) + 5 // TCP acknowledgment [byte 4]
			header[50] = byte(i) + 6 // TCP checksum [byte 1]
			header[51] = byte(i) + 7 // TCP checksum [byte 2]
		}

		b.StopTimer()
	})

	b.Run("multi dictionaries", func(b *testing.B) {
		output := bytes.NewBuffer(make([]byte, 0, 64*1024*1024))
		w := NewWriter(output)

		header := make([]byte, len(testIPv4TCPFrameHeader1))
		copy(header, testIPv4TCPFrameHeader1)

		b.ReportAllocs()
		b.ResetTimer()

		var err error
		for i := 0; i < b.N; i++ {
			_, err = w.Write(header)
			if err != nil {
				b.Fatal(err)
			}

			// data that change frequently
			header[17] = byte(i) + 1 // IPv4 Total Length [byte 2]
			header[19] = byte(i) + 2 // IPv4 ID [byte 2]
			header[25] = byte(i) + 3 // IPv4 checksum [byte 2]

			header[41] = byte(i) + 4 // TCP Sequence [byte 4]
			header[45] = byte(i) + 5 // TCP acknowledgment [byte 4]
			header[50] = byte(i) + 6 // TCP checksum [byte 1]
			header[51] = byte(i) + 7 // TCP checksum [byte 2]

			// change destination port for create more dictionaries
			header[34] = byte(i) + 8
		}

		b.StopTimer()
	})
}

func benchmarkWriterWriteEthernetIPv4UDP(b *testing.B) {
	b.Run("single dictionary", func(b *testing.B) {
		output := bytes.NewBuffer(make([]byte, 0, 64*1024*1024))
		w := NewWriter(output)

		header := make([]byte, len(testIPv4UDPFrameHeader1))
		copy(header, testIPv4UDPFrameHeader1)

		b.ReportAllocs()
		b.ResetTimer()

		var err error
		for i := 0; i < b.N; i++ {
			_, err = w.Write(header)
			if err != nil {
				b.Fatal(err)
			}

			// data that change frequently
			header[17] = byte(i) + 1 // IPv4 Total Length [byte 2]
			header[19] = byte(i) + 2 // IPv4 ID [byte 2]
			header[25] = byte(i) + 3 // IPv4 checksum [byte 2]

			header[39] = byte(i) + 4 // UDP length [byte 4]
			header[40] = byte(i) + 5 // UDP checksum [byte 1]
			header[41] = byte(i) + 6 // UDP checksum [byte 2]
		}

		b.StopTimer()
	})

	b.Run("multi dictionaries", func(b *testing.B) {
		output := bytes.NewBuffer(make([]byte, 0, 64*1024*1024))
		w := NewWriter(output)

		header := make([]byte, len(testIPv4UDPFrameHeader1))
		copy(header, testIPv4UDPFrameHeader1)

		b.ReportAllocs()
		b.ResetTimer()

		var err error
		for i := 0; i < b.N; i++ {
			_, err = w.Write(header)
			if err != nil {
				b.Fatal(err)
			}

			// data that change frequently
			header[17] = byte(i) + 1 // IPv4 Total Length [byte 2]
			header[19] = byte(i) + 2 // IPv4 ID [byte 2]
			header[25] = byte(i) + 3 // IPv4 checksum [byte 2]

			header[39] = byte(i) + 4 // UDP length [byte 4]
			header[40] = byte(i) + 5 // UDP checksum [byte 1]
			header[41] = byte(i) + 6 // UDP checksum [byte 2]

			// change destination port for create more dictionaries
			header[34] = byte(i) + 7
		}

		b.StopTimer()
	})
}

func benchmarkWriterWriteEthernetIPv6TCP(b *testing.B) {
	b.Run("single dictionary", func(b *testing.B) {
		output := bytes.NewBuffer(make([]byte, 0, 64*1024*1024))
		w := NewWriter(output)

		header := make([]byte, len(testIPv6TCPFrameHeader1))
		copy(header, testIPv6TCPFrameHeader1)

		b.ReportAllocs()
		b.ResetTimer()

		var err error
		for i := 0; i < b.N; i++ {
			_, err = w.Write(header)
			if err != nil {
				b.Fatal(err)
			}

			// data that change frequently
			header[19] = byte(i) + 1 // IPv6 payload length [byte 2]

			header[61] = byte(i) + 2 // TCP Sequence [byte 4]
			header[65] = byte(i) + 3 // TCP acknowledgment [byte 4]
			header[70] = byte(i) + 4 // TCP checksum [byte 1]
			header[71] = byte(i) + 5 // TCP checksum [byte 2]
		}

		b.StopTimer()
	})

	b.Run("multi dictionaries", func(b *testing.B) {
		output := bytes.NewBuffer(make([]byte, 0, 64*1024*1024))
		w := NewWriter(output)

		header := make([]byte, len(testIPv6TCPFrameHeader1))
		copy(header, testIPv6TCPFrameHeader1)

		b.ReportAllocs()
		b.ResetTimer()

		var err error
		for i := 0; i < b.N; i++ {
			_, err = w.Write(header)
			if err != nil {
				b.Fatal(err)
			}

			// data that change frequently
			header[19] = byte(i) + 1 // IPv6 payload length [byte 2]

			header[61] = byte(i) + 2 // TCP Sequence [byte 4]
			header[65] = byte(i) + 3 // TCP acknowledgment [byte 4]
			header[70] = byte(i) + 4 // TCP checksum [byte 1]
			header[71] = byte(i) + 5 // TCP checksum [byte 2]

			// change destination port for create more dictionaries
			header[54] = byte(i) + 6
		}

		b.StopTimer()
	})
}

func benchmarkWriterWriteEthernetIPv6UDP(b *testing.B) {
	b.Run("single dictionary", func(b *testing.B) {
		output := bytes.NewBuffer(make([]byte, 0, 64*1024*1024))
		w := NewWriter(output)

		header := make([]byte, len(testIPv6UDPFrameHeader1))
		copy(header, testIPv6UDPFrameHeader1)

		b.ReportAllocs()
		b.ResetTimer()

		var err error
		for i := 0; i < b.N; i++ {
			_, err = w.Write(header)
			if err != nil {
				b.Fatal(err)
			}

			// data that change frequently
			header[19] = byte(i) + 1 // IPv6 payload length [byte 2]

			header[59] = byte(i) + 2 // UDP length [byte 4]
			header[60] = byte(i) + 3 // UDP checksum [byte 1]
			header[61] = byte(i) + 4 // UDP checksum [byte 2]
		}

		b.StopTimer()
	})

	b.Run("multi dictionaries", func(b *testing.B) {
		output := bytes.NewBuffer(make([]byte, 0, 64*1024*1024))
		w := NewWriter(output)

		header := make([]byte, len(testIPv6UDPFrameHeader1))
		copy(header, testIPv6UDPFrameHeader1)

		b.ReportAllocs()
		b.ResetTimer()

		var err error
		for i := 0; i < b.N; i++ {
			_, err = w.Write(header)
			if err != nil {
				b.Fatal(err)
			}

			// data that change frequently
			header[19] = byte(i) + 1 // IPv6 payload length [byte 2]

			header[59] = byte(i) + 2 // UDP length [byte 4]
			header[60] = byte(i) + 3 // UDP checksum [byte 1]
			header[61] = byte(i) + 4 // UDP checksum [byte 2]

			// change destination port for create more dictionaries
			header[54] = byte(i) + 5
		}

		b.StopTimer()
	})
}

func benchmarkWriterWriteCustomFrameHeader(b *testing.B) {
	b.Run("single dictionary", func(b *testing.B) {
		output := bytes.NewBuffer(make([]byte, 0, 64*1024*1024))
		w := NewWriter(output)

		header := make([]byte, 64)
		copy(header, testIPv4TCPFrameHeader1)

		b.ReportAllocs()
		b.ResetTimer()

		var err error
		for i := 0; i < b.N; i++ {
			_, err = w.Write(header)
			if err != nil {
				b.Fatal(err)
			}

			// change a little
			for j := 0; j < len(header)/minDiffDiv-2; j++ {
				header[j] = byte(i) + 1
			}
		}

		b.StopTimer()
	})

	b.Run("multi dictionaries", func(b *testing.B) {
		output := bytes.NewBuffer(make([]byte, 0, 64*1024*1024))
		w := NewWriter(output)

		header := make([]byte, 64)
		copy(header, testIPv4TCPFrameHeader1)

		b.ReportAllocs()
		b.ResetTimer()

		var err error
		for i := 0; i < b.N; i++ {
			_, err = w.Write(header)
			if err != nil {
				b.Fatal(err)
			}

			// change a lot
			for j := 0; j < len(header)/maxDiffDiv+2; j++ {
				header[j] = byte(i) + 1
			}
		}

		b.StopTimer()
	})
}
