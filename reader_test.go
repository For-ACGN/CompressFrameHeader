package cfh

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"testing"

	"github.com/agiledragon/gomonkey/v2"
	"github.com/stretchr/testify/require"
)

func TestNewReader(t *testing.T) {
	t.Run("common", func(t *testing.T) {
		output := bytes.NewBuffer(make([]byte, 0, 64))

		r := NewReader(output)
		require.NotNil(t, r)
	})

	t.Run("too small dictionary size", func(t *testing.T) {
		output := bytes.NewBuffer(make([]byte, 0, 64))

		r, err := NewReaderWithSize(output, 0)
		require.EqualError(t, err, "dictionary size cannot less than 1")
		require.Nil(t, r)
	})

	t.Run("too large dictionary size", func(t *testing.T) {
		output := bytes.NewBuffer(make([]byte, 0, 64))

		r, err := NewReaderWithSize(output, MaxDictionarySize+1)
		require.EqualError(t, err, "dictionary size cannot greater than 256")
		require.Nil(t, r)
	})

	t.Run("panic with default parameters", func(t *testing.T) {
		outputs := []interface{}{nil, errors.New("monkey error")}
		patch := gomonkey.ApplyFuncReturn(NewReaderWithSize, outputs...)
		defer patch.Reset()

		output := bytes.NewBuffer(make([]byte, 0, 64))

		defer func() {
			r := recover()
			require.NotNil(t, r)
		}()
		_ = NewReader(output)
	})
}

func TestReader_Read(t *testing.T) {
	t.Run("read remaining data", func(t *testing.T) {
		output := bytes.NewBuffer(make([]byte, 0, 128))

		w := NewWriter(output)

		n, err := w.Write(testIPv4TCPFrameHeader1)
		require.NoError(t, err)
		require.Equal(t, len(testIPv4TCPFrameHeader1), n)

		r := NewReader(output)

		buf1 := make([]byte, len(testIPv4TCPFrameHeader1)-16)
		n, err = r.Read(buf1)
		require.NoError(t, err)
		require.Equal(t, len(buf1), n)

		buf2 := make([]byte, 16)
		n, err = r.Read(buf2)
		require.NoError(t, err)
		require.Equal(t, len(buf2), n)

		require.Equal(t, testIPv4TCPFrameHeader1, append(buf1, buf2...))
	})

	t.Run("read empty buffer", func(t *testing.T) {
		output := bytes.NewBuffer(make([]byte, 0, 128))
		r := NewReader(output)

		n, err := r.Read(nil)
		require.NoError(t, err)
		require.Zero(t, n)
	})

	t.Run("read with too large buffer", func(t *testing.T) {
		output := bytes.NewBuffer(make([]byte, 0, 64))

		r := NewReader(output)

		buf := make([]byte, 1024)
		n, err := r.Read(buf)
		require.EqualError(t, err, "read with too large buffer")
		require.Zero(t, n)
	})

	t.Run("read after appear error", func(t *testing.T) {
		output := bytes.NewBuffer(make([]byte, 0, 64))

		r := NewReader(output)

		buf := make([]byte, MaxFrameHeaderSize)
		n, err := r.Read(buf)
		require.EqualError(t, err, "failed to read decompress command: EOF")
		require.Zero(t, n)

		n, err = r.Read(buf)
		require.EqualError(t, err, "failed to read decompress command: EOF")
		require.Zero(t, n)
	})

	t.Run("failed to read decompress command", func(t *testing.T) {
		output := bytes.NewBuffer(make([]byte, 0, 64))

		r := NewReader(output)

		buf := make([]byte, MaxFrameHeaderSize)
		n, err := r.Read(buf)
		require.EqualError(t, err, "failed to read decompress command: EOF")
		require.Zero(t, n)
	})

	t.Run("invalid decompress command", func(t *testing.T) {
		output := bytes.NewBuffer(make([]byte, 0, 64))
		output.WriteByte(0)

		r := NewReader(output)

		buf := make([]byte, MaxFrameHeaderSize)
		n, err := r.Read(buf)
		require.EqualError(t, err, "invalid decompress command: 0")
		require.Zero(t, n)
	})

	t.Run("add dictionary", func(t *testing.T) {
		t.Run("failed to read dictionary size", func(t *testing.T) {
			output := bytes.NewBuffer(make([]byte, 0, 64))
			output.WriteByte(cmdAddDict)

			r := NewReader(output)

			buf := make([]byte, MaxFrameHeaderSize)
			n, err := r.Read(buf)
			require.EqualError(t, err, "failed to read dictionary size: EOF")
			require.Zero(t, n)
		})

		t.Run("read empty dictionary", func(t *testing.T) {
			output := bytes.NewBuffer(make([]byte, 0, 64))
			output.WriteByte(cmdAddDict)
			output.WriteByte(0) // dictionary size

			r := NewReader(output)

			buf := make([]byte, MaxFrameHeaderSize)
			n, err := r.Read(buf)
			require.EqualError(t, err, "read empty dictionary")
			require.Zero(t, n)
		})

		t.Run("failed to read dictionary data", func(t *testing.T) {
			output := bytes.NewBuffer(make([]byte, 0, 64))
			output.WriteByte(cmdAddDict)
			output.WriteByte(1) // dictionary size

			r := NewReader(output)

			buf := make([]byte, MaxFrameHeaderSize)
			n, err := r.Read(buf)
			require.EqualError(t, err, "failed to read dictionary data: EOF")
			require.Zero(t, n)
		})
	})

	t.Run("read changed data", func(t *testing.T) {
		t.Run("failed to read dictionary index", func(t *testing.T) {
			output := bytes.NewBuffer(make([]byte, 0, 64))
			output.WriteByte(cmdData)

			r := NewReader(output)

			buf := make([]byte, MaxFrameHeaderSize)
			n, err := r.Read(buf)
			require.EqualError(t, err, "failed to read dictionary index: EOF")
			require.Zero(t, n)
		})

		t.Run("read invalid dictionary index", func(t *testing.T) {
			output := bytes.NewBuffer(make([]byte, 0, 64))
			output.WriteByte(cmdData)
			output.WriteByte(0) // dictionary index

			r := NewReader(output)

			buf := make([]byte, MaxFrameHeaderSize)
			n, err := r.Read(buf)
			require.EqualError(t, err, "read invalid dictionary index: 0")
			require.Zero(t, n)
		})

		t.Run("failed to read the number of changed data", func(t *testing.T) {
			output := bytes.NewBuffer(make([]byte, 0, 64))
			output.WriteByte(cmdData)
			output.WriteByte(0) // dictionary index

			r := NewReader(output)
			r.dict[0] = []byte{1, 2, 3, 4}

			buf := make([]byte, MaxFrameHeaderSize)
			n, err := r.Read(buf)
			require.EqualError(t, err, "failed to read the number of changed data: EOF")
			require.Zero(t, n)
		})

		t.Run("read invalid changed data", func(t *testing.T) {
			output := bytes.NewBuffer(make([]byte, 0, 64))
			output.WriteByte(cmdData)
			output.WriteByte(0) // dictionary index
			output.WriteByte(5) // the number of changed data

			r := NewReader(output)
			r.dict[0] = []byte{1, 2, 3, 4}

			buf := make([]byte, MaxFrameHeaderSize)
			n, err := r.Read(buf)
			require.EqualError(t, err, "read invalid changed data size: 5")
			require.Zero(t, n)
		})

		t.Run("failed to read changed data", func(t *testing.T) {
			output := bytes.NewBuffer(make([]byte, 0, 64))
			output.WriteByte(cmdData)
			output.WriteByte(0) // dictionary index
			output.WriteByte(2) // the number of changed data

			r := NewReader(output)
			r.dict[0] = []byte{1, 2, 3, 4}

			buf := make([]byte, MaxFrameHeaderSize)
			n, err := r.Read(buf)
			require.EqualError(t, err, "failed to read changed data: EOF")
			require.Zero(t, n)
		})

		t.Run("invalid changed data index", func(t *testing.T) {
			output := bytes.NewBuffer(make([]byte, 0, 64))
			output.WriteByte(cmdData)
			output.WriteByte(0)   // dictionary index
			output.WriteByte(1)   // the number of changed data
			output.WriteByte(4)   // changed data index
			output.WriteByte(123) // changed data

			r := NewReader(output)
			r.dict[0] = []byte{1, 2, 3, 4}

			buf := make([]byte, MaxFrameHeaderSize)
			n, err := r.Read(buf)
			require.EqualError(t, err, "invalid changed data index: 4")
			require.Zero(t, n)
		})
	})

	t.Run("reuse previous data", func(t *testing.T) {
		t.Run("failed to read dictionary index", func(t *testing.T) {
			output := bytes.NewBuffer(make([]byte, 0, 64))
			output.WriteByte(cmdPrev)

			r := NewReader(output)

			buf := make([]byte, MaxFrameHeaderSize)
			n, err := r.Read(buf)
			require.EqualError(t, err, "failed to read dictionary index: EOF")
			require.Zero(t, n)
		})

		t.Run("read invalid dictionary index", func(t *testing.T) {
			output := bytes.NewBuffer(make([]byte, 0, 64))
			output.WriteByte(cmdPrev)
			output.WriteByte(0) // dictionary index

			r := NewReader(output)

			buf := make([]byte, MaxFrameHeaderSize)
			n, err := r.Read(buf)
			require.EqualError(t, err, "read invalid dictionary index: 0")
			require.Zero(t, n)
		})
	})
}

func TestReader_Fuzz(t *testing.T) {
	data := make([]byte, 128)
	reader := bytes.NewReader(data)
	buf := make([]byte, MaxFrameHeaderSize)
	for i := 0; i < 128*1024; i++ {
		_, err := rand.Read(data)
		require.NoError(t, err)
		_, err = reader.Seek(0, io.SeekStart)
		require.NoError(t, err)

		r := NewReader(reader)
		_, _ = r.Read(buf)
	}
}

func BenchmarkReader_Read(b *testing.B) {
	b.Run("Ethernet IPv4 TCP", benchmarkReaderReadEthernetIPv4TCP)
	b.Run("Ethernet IPv4 UDP", benchmarkReaderReadEthernetIPv4UDP)
	b.Run("Ethernet IPv6 TCP", benchmarkReaderReadEthernetIPv6TCP)
	b.Run("Ethernet IPv6 UDP", benchmarkReaderReadEthernetIPv6UDP)
	b.Run("Custom Frame Header", benchmarkReaderReadCustomFrameHeader)
}

func benchmarkReaderReadEthernetIPv4TCP(b *testing.B) {
	b.Run("single dictionary", func(b *testing.B) {
		output := bytes.NewBuffer(make([]byte, 0, 1024*1024))
		w := NewWriter(output)

		header := make([]byte, len(testIPv4TCPFrameHeader1))
		copy(header, testIPv4TCPFrameHeader1)

		var err error
		for i := 0; i < 1024; i++ {
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

		reader := bytes.NewReader(output.Bytes())

		r := NewReader(reader)
		buf := make([]byte, len(testIPv4TCPFrameHeader1))

		b.ReportAllocs()
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			_, err = r.Read(buf)
			if err != nil {
				b.Fatal(err)
			}

			if reader.Len() != 0 {
				continue
			}
			_, err = reader.Seek(0, io.SeekStart)
			if err != nil {
				b.Fatal(err)
			}
		}

		b.StopTimer()
	})

	b.Run("multi dictionaries", func(b *testing.B) {
		output := bytes.NewBuffer(make([]byte, 0, 1024*1024))
		w := NewWriter(output)

		header := make([]byte, len(testIPv4TCPFrameHeader1))
		copy(header, testIPv4TCPFrameHeader1)

		var err error
		for i := 0; i < 1024; i++ {
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

		reader := bytes.NewReader(output.Bytes())

		r := NewReader(reader)
		buf := make([]byte, len(testIPv4TCPFrameHeader1))

		b.ReportAllocs()
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			_, err = r.Read(buf)
			if err != nil {
				b.Fatal(err)
			}

			if reader.Len() != 0 {
				continue
			}
			_, err = reader.Seek(0, io.SeekStart)
			if err != nil {
				b.Fatal(err)
			}
		}

		b.StopTimer()
	})
}

func benchmarkReaderReadEthernetIPv4UDP(b *testing.B) {
	b.Run("single dictionary", func(b *testing.B) {
		output := bytes.NewBuffer(make([]byte, 0, 1024*1024))
		w := NewWriter(output)

		header := make([]byte, len(testIPv4UDPFrameHeader1))
		copy(header, testIPv4UDPFrameHeader1)

		var err error
		for i := 0; i < 1024; i++ {
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

		reader := bytes.NewReader(output.Bytes())

		r := NewReader(reader)
		buf := make([]byte, len(testIPv4UDPFrameHeader1))

		b.ReportAllocs()
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			_, err = r.Read(buf)
			if err != nil {
				b.Fatal(err)
			}

			if reader.Len() != 0 {
				continue
			}
			_, err = reader.Seek(0, io.SeekStart)
			if err != nil {
				b.Fatal(err)
			}
		}

		b.StopTimer()
	})

	b.Run("multi dictionaries", func(b *testing.B) {
		output := bytes.NewBuffer(make([]byte, 0, 1024*1024))
		w := NewWriter(output)

		header := make([]byte, len(testIPv4UDPFrameHeader1))
		copy(header, testIPv4UDPFrameHeader1)

		var err error
		for i := 0; i < 1024; i++ {
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

		reader := bytes.NewReader(output.Bytes())

		r := NewReader(reader)
		buf := make([]byte, len(testIPv4UDPFrameHeader1))

		b.ReportAllocs()
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			_, err = r.Read(buf)
			if err != nil {
				b.Fatal(err)
			}

			if reader.Len() != 0 {
				continue
			}
			_, err = reader.Seek(0, io.SeekStart)
			if err != nil {
				b.Fatal(err)
			}
		}

		b.StopTimer()
	})
}

func benchmarkReaderReadEthernetIPv6TCP(b *testing.B) {
	b.Run("single dictionary", func(b *testing.B) {
		output := bytes.NewBuffer(make([]byte, 0, 1024*1024))
		w := NewWriter(output)

		header := make([]byte, len(testIPv6TCPFrameHeader1))
		copy(header, testIPv6TCPFrameHeader1)

		var err error
		for i := 0; i < 1024; i++ {
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

		reader := bytes.NewReader(output.Bytes())

		r := NewReader(reader)
		buf := make([]byte, len(testIPv6TCPFrameHeader1))

		b.ReportAllocs()
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			_, err = r.Read(buf)
			if err != nil {
				b.Fatal(err)
			}

			if reader.Len() != 0 {
				continue
			}
			_, err = reader.Seek(0, io.SeekStart)
			if err != nil {
				b.Fatal(err)
			}
		}

		b.StopTimer()
	})

	b.Run("multi dictionaries", func(b *testing.B) {
		output := bytes.NewBuffer(make([]byte, 0, 1024*1024))
		w := NewWriter(output)

		header := make([]byte, len(testIPv6TCPFrameHeader1))
		copy(header, testIPv6TCPFrameHeader1)

		var err error
		for i := 0; i < 1024; i++ {
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

		reader := bytes.NewReader(output.Bytes())

		r := NewReader(reader)
		buf := make([]byte, len(testIPv6TCPFrameHeader1))

		b.ReportAllocs()
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			_, err = r.Read(buf)
			if err != nil {
				b.Fatal(err)
			}

			if reader.Len() != 0 {
				continue
			}
			_, err = reader.Seek(0, io.SeekStart)
			if err != nil {
				b.Fatal(err)
			}
		}

		b.StopTimer()
	})
}

func benchmarkReaderReadEthernetIPv6UDP(b *testing.B) {
	b.Run("single dictionary", func(b *testing.B) {
		output := bytes.NewBuffer(make([]byte, 0, 1024*1024))
		w := NewWriter(output)

		header := make([]byte, len(testIPv6UDPFrameHeader1))
		copy(header, testIPv6UDPFrameHeader1)

		var err error
		for i := 0; i < 1024; i++ {
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

		reader := bytes.NewReader(output.Bytes())

		r := NewReader(reader)
		buf := make([]byte, len(testIPv6UDPFrameHeader1))

		b.ReportAllocs()
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			_, err = r.Read(buf)
			if err != nil {
				b.Fatal(err)
			}

			if reader.Len() != 0 {
				continue
			}
			_, err = reader.Seek(0, io.SeekStart)
			if err != nil {
				b.Fatal(err)
			}
		}

		b.StopTimer()
	})

	b.Run("multi dictionaries", func(b *testing.B) {
		output := bytes.NewBuffer(make([]byte, 0, 1024*1024))
		w := NewWriter(output)

		header := make([]byte, len(testIPv6UDPFrameHeader1))
		copy(header, testIPv6UDPFrameHeader1)

		var err error
		for i := 0; i < 1024; i++ {
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

		reader := bytes.NewReader(output.Bytes())

		r := NewReader(reader)
		buf := make([]byte, len(testIPv6UDPFrameHeader1))

		b.ReportAllocs()
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			_, err = r.Read(buf)
			if err != nil {
				b.Fatal(err)
			}

			if reader.Len() != 0 {
				continue
			}
			_, err = reader.Seek(0, io.SeekStart)
			if err != nil {
				b.Fatal(err)
			}
		}

		b.StopTimer()
	})
}

func benchmarkReaderReadCustomFrameHeader(b *testing.B) {
	b.Run("single dictionary", func(b *testing.B) {
		output := bytes.NewBuffer(make([]byte, 0, 1024*1024))
		w := NewWriter(output)

		header := make([]byte, 64)
		copy(header, testIPv4TCPFrameHeader1)

		var err error
		for i := 0; i < 1024; i++ {
			_, err = w.Write(header)
			if err != nil {
				b.Fatal(err)
			}

			// change a little
			for j := 0; j < len(header)/minDiffDiv-2; j++ {
				header[j] = byte(i) + 1
			}
		}

		reader := bytes.NewReader(output.Bytes())

		r := NewReader(reader)
		buf := make([]byte, len(header))

		b.ReportAllocs()
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			_, err = r.Read(buf)
			if err != nil {
				b.Fatal(err)
			}

			if reader.Len() != 0 {
				continue
			}
			_, err = reader.Seek(0, io.SeekStart)
			if err != nil {
				b.Fatal(err)
			}
		}

		b.StopTimer()
	})

	b.Run("multi dictionaries", func(b *testing.B) {
		output := bytes.NewBuffer(make([]byte, 0, 1024*1024))
		w := NewWriter(output)

		header := make([]byte, 64)
		copy(header, testIPv4TCPFrameHeader1)

		var err error
		for i := 0; i < 1024; i++ {
			_, err = w.Write(header)
			if err != nil {
				b.Fatal(err)
			}

			// change a little
			for j := 0; j < len(header)/maxDiffDiv+2; j++ {
				header[j] = byte(i) + 1
			}
		}

		reader := bytes.NewReader(output.Bytes())

		r := NewReader(reader)
		buf := make([]byte, len(header))

		b.ReportAllocs()
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			_, err = r.Read(buf)
			if err != nil {
				b.Fatal(err)
			}

			if reader.Len() != 0 {
				continue
			}
			_, err = reader.Seek(0, io.SeekStart)
			if err != nil {
				b.Fatal(err)
			}
		}

		b.StopTimer()
	})
}
