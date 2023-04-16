package cfh

import (
	"bytes"
	"errors"
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

		r, err := NewReaderWithSize(output, 4096)
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

		buf := make([]byte, 256)
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

		buf := make([]byte, 256)
		n, err := r.Read(buf)
		require.EqualError(t, err, "failed to read decompress command: EOF")
		require.Zero(t, n)
	})

	t.Run("invalid decompress command", func(t *testing.T) {
		output := bytes.NewBuffer(make([]byte, 0, 64))
		output.WriteByte(0)

		r := NewReader(output)

		buf := make([]byte, 256)
		n, err := r.Read(buf)
		require.EqualError(t, err, "invalid decompress command: 0")
		require.Zero(t, n)
	})

	t.Run("add dictionary", func(t *testing.T) {
		t.Run("failed to read dictionary size", func(t *testing.T) {
			output := bytes.NewBuffer(make([]byte, 0, 64))
			output.WriteByte(cmdAddDict)

			r := NewReader(output)

			buf := make([]byte, 256)
			n, err := r.Read(buf)
			require.EqualError(t, err, "failed to read dictionary size: EOF")
			require.Zero(t, n)
		})

		t.Run("read empty dictionary", func(t *testing.T) {
			output := bytes.NewBuffer(make([]byte, 0, 64))
			output.WriteByte(cmdAddDict)
			output.WriteByte(0) // dictionary size

			r := NewReader(output)

			buf := make([]byte, 256)
			n, err := r.Read(buf)
			require.EqualError(t, err, "read empty dictionary")
			require.Zero(t, n)
		})

		t.Run("failed to read dictionary data", func(t *testing.T) {
			output := bytes.NewBuffer(make([]byte, 0, 64))
			output.WriteByte(cmdAddDict)
			output.WriteByte(1) // dictionary size

			r := NewReader(output)

			buf := make([]byte, 256)
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

			buf := make([]byte, 256)
			n, err := r.Read(buf)
			require.EqualError(t, err, "failed to read dictionary index: EOF")
			require.Zero(t, n)
		})

		t.Run("read invalid dictionary index", func(t *testing.T) {
			output := bytes.NewBuffer(make([]byte, 0, 64))
			output.WriteByte(cmdData)
			output.WriteByte(0) // dictionary index

			r := NewReader(output)

			buf := make([]byte, 256)
			n, err := r.Read(buf)
			require.EqualError(t, err, "read invalid dictionary index: 0")
			require.Zero(t, n)
		})

		t.Run("failed to read the number of changed data", func(t *testing.T) {
			output := bytes.NewBuffer(make([]byte, 0, 64))
			output.WriteByte(cmdData)
			output.WriteByte(0) // dictionary index

			r := NewReader(output)
			r.(*Reader).dict[0] = []byte{1, 2, 3, 4}

			buf := make([]byte, 256)
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
			r.(*Reader).dict[0] = []byte{1, 2, 3, 4}

			buf := make([]byte, 256)
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
			r.(*Reader).dict[0] = []byte{1, 2, 3, 4}

			buf := make([]byte, 256)
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
			r.(*Reader).dict[0] = []byte{1, 2, 3, 4}

			buf := make([]byte, 256)
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

			buf := make([]byte, 256)
			n, err := r.Read(buf)
			require.EqualError(t, err, "failed to read dictionary index: EOF")
			require.Zero(t, n)
		})

		t.Run("read invalid dictionary index", func(t *testing.T) {
			output := bytes.NewBuffer(make([]byte, 0, 64))
			output.WriteByte(cmdPrev)
			output.WriteByte(0) // dictionary index

			r := NewReader(output)

			buf := make([]byte, 256)
			n, err := r.Read(buf)
			require.EqualError(t, err, "read invalid dictionary index: 0")
			require.Zero(t, n)
		})
	})
}
