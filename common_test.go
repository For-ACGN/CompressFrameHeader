package cfh

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

var (
	testEthernet1 = "d8ba1192c572d8af159ac5d10800" // IPv4
	testEthernet2 = "d8ba1192c572d8af159ac5d20800" // IPv4
	testEthernet3 = "d8ba1192c572d8af159ac5d386dd" // IPv6
	testEthernet4 = "d8ba1192c572d8af159ac5d486dd" // IPv6

	testIPv4H1 = "450405c8574d40003706b63514983c5fc0a81f0a" // TCP
	testIPv4H2 = "450405c8575d40003706b63514983c5fc0a81f0a" // TCP
	testIPv4H3 = "450405c8576d40003711b63514983c5fc0a81f0a" // UDP
	testIPv4H4 = "450405c8577d40003711b63514983c5fc0a81f0a" // UDP

	testIPv6H1 = "6043670105a0062b24108c016c2a103d000000afb00239ab24108a2aa084b4a02127e9cada1240f1" // TCP
	testIPv6H2 = "6043670205a0062b24108c016c2a103d000000afb00239ab24108a2aa084b4a02127e9cada1240f1" // TCP
	testIPv6H3 = "6043670305a0112b24108c016c2a103d000000afb00239ab24108a2aa084b4a02127e9cada1240f1" // UDP
	testIPv6H4 = "6043670405a0112b24108c016c2a103d000000afb00239ab24108a2aa084b4a02127e9cada1240f1" // UDP

	testTCPH1 = "01bbebd71561ddfc151e1385501003d037390000"
	testTCPH2 = "01bbebd81661ddfc151e1385501003d037390000"

	testUDPH1 = "fb7b003500385f66"
	testUDPH2 = "fb7b003600385f66"

	testIPv4TCPFrameHeader1 = testMustHexDecodeString(testEthernet1 + testIPv4H1 + testTCPH1)
	testIPv4TCPFrameHeader2 = testMustHexDecodeString(testEthernet1 + testIPv4H1 + testTCPH2)
	testIPv4TCPFrameHeader3 = testMustHexDecodeString(testEthernet1 + testIPv4H2 + testTCPH1)
	testIPv4TCPFrameHeader4 = testMustHexDecodeString(testEthernet1 + testIPv4H2 + testTCPH2)
	testIPv4TCPFrameHeader5 = testMustHexDecodeString(testEthernet2 + testIPv4H1 + testTCPH1)
	testIPv4TCPFrameHeader6 = testMustHexDecodeString(testEthernet2 + testIPv4H1 + testTCPH2)
	testIPv4TCPFrameHeader7 = testMustHexDecodeString(testEthernet2 + testIPv4H2 + testTCPH1)
	testIPv4TCPFrameHeader8 = testMustHexDecodeString(testEthernet2 + testIPv4H2 + testTCPH2)

	testIPv4UDPFrameHeader1 = testMustHexDecodeString(testEthernet1 + testIPv4H3 + testUDPH1)
	testIPv4UDPFrameHeader2 = testMustHexDecodeString(testEthernet1 + testIPv4H3 + testUDPH2)
	testIPv4UDPFrameHeader3 = testMustHexDecodeString(testEthernet1 + testIPv4H4 + testUDPH1)
	testIPv4UDPFrameHeader4 = testMustHexDecodeString(testEthernet1 + testIPv4H4 + testUDPH2)
	testIPv4UDPFrameHeader5 = testMustHexDecodeString(testEthernet2 + testIPv4H3 + testUDPH1)
	testIPv4UDPFrameHeader6 = testMustHexDecodeString(testEthernet2 + testIPv4H3 + testUDPH2)
	testIPv4UDPFrameHeader7 = testMustHexDecodeString(testEthernet2 + testIPv4H4 + testUDPH1)
	testIPv4UDPFrameHeader8 = testMustHexDecodeString(testEthernet2 + testIPv4H4 + testUDPH2)

	testIPv6TCPFrameHeader1 = testMustHexDecodeString(testEthernet3 + testIPv6H1 + testTCPH1)
	testIPv6TCPFrameHeader2 = testMustHexDecodeString(testEthernet3 + testIPv6H1 + testTCPH2)
	testIPv6TCPFrameHeader3 = testMustHexDecodeString(testEthernet3 + testIPv6H2 + testTCPH1)
	testIPv6TCPFrameHeader4 = testMustHexDecodeString(testEthernet3 + testIPv6H2 + testTCPH2)
	testIPv6TCPFrameHeader5 = testMustHexDecodeString(testEthernet4 + testIPv6H1 + testTCPH1)
	testIPv6TCPFrameHeader6 = testMustHexDecodeString(testEthernet4 + testIPv6H1 + testTCPH2)
	testIPv6TCPFrameHeader7 = testMustHexDecodeString(testEthernet4 + testIPv6H2 + testTCPH1)
	testIPv6TCPFrameHeader8 = testMustHexDecodeString(testEthernet4 + testIPv6H2 + testTCPH2)

	testIPv6UDPFrameHeader1 = testMustHexDecodeString(testEthernet3 + testIPv6H3 + testUDPH1)
	testIPv6UDPFrameHeader2 = testMustHexDecodeString(testEthernet3 + testIPv6H3 + testUDPH2)
	testIPv6UDPFrameHeader3 = testMustHexDecodeString(testEthernet3 + testIPv6H4 + testUDPH1)
	testIPv6UDPFrameHeader4 = testMustHexDecodeString(testEthernet3 + testIPv6H4 + testUDPH2)
	testIPv6UDPFrameHeader5 = testMustHexDecodeString(testEthernet4 + testIPv6H3 + testUDPH1)
	testIPv6UDPFrameHeader6 = testMustHexDecodeString(testEthernet4 + testIPv6H3 + testUDPH2)
	testIPv6UDPFrameHeader7 = testMustHexDecodeString(testEthernet4 + testIPv6H4 + testUDPH1)
	testIPv6UDPFrameHeader8 = testMustHexDecodeString(testEthernet4 + testIPv6H4 + testUDPH2)
)

var testFrameHeaders = [][]byte{
	testIPv4TCPFrameHeader1, testIPv4TCPFrameHeader2, testIPv4TCPFrameHeader3, testIPv4TCPFrameHeader4,
	testIPv4TCPFrameHeader5, testIPv4TCPFrameHeader6, testIPv4TCPFrameHeader7, testIPv4TCPFrameHeader8,

	testIPv4UDPFrameHeader1, testIPv4UDPFrameHeader2, testIPv4UDPFrameHeader3, testIPv4UDPFrameHeader4,
	testIPv4UDPFrameHeader5, testIPv4UDPFrameHeader6, testIPv4UDPFrameHeader7, testIPv4UDPFrameHeader8,

	testIPv6TCPFrameHeader1, testIPv6TCPFrameHeader2, testIPv6TCPFrameHeader3, testIPv6TCPFrameHeader4,
	testIPv6TCPFrameHeader5, testIPv6TCPFrameHeader6, testIPv6TCPFrameHeader7, testIPv6TCPFrameHeader8,

	testIPv6UDPFrameHeader1, testIPv6UDPFrameHeader2, testIPv6UDPFrameHeader3, testIPv6UDPFrameHeader4,
	testIPv6UDPFrameHeader5, testIPv6UDPFrameHeader6, testIPv6UDPFrameHeader7, testIPv6UDPFrameHeader8,
}

func testMustHexDecodeString(s string) []byte {
	data, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return data
}

func testGenerateFrameHeaders(t *testing.T) [][]byte {
	headers := make([][]byte, 512*1024)
	typ := make([]byte, 1)
	idx := make([]byte, 2)
	for i := 0; i < len(headers); i++ {
		// select frame header type
		_, err := rand.Read(typ)
		require.NoError(t, err)
		switch typ[0] % 5 {
		case 0: // IPv4 + TCP
			header := make([]byte, ethernetIPv4TCPSize)
			copy(header, testIPv4TCPFrameHeader1)
			// random change data
			for j := 0; j < 3; j++ {
				_, err = rand.Read(idx)
				require.NoError(t, err)
				index := binary.BigEndian.Uint16(idx) % ethernetIPv4TCPSize
				header[index] = idx[1]
			}
			headers[i] = header
		case 1: // IPv4 + UDP
			header := make([]byte, ethernetIPv4UDPSize)
			copy(header, testIPv4UDPFrameHeader1)
			// random change data
			for j := 0; j < 2; j++ {
				_, err = rand.Read(idx)
				require.NoError(t, err)
				index := binary.BigEndian.Uint16(idx) % ethernetIPv4UDPSize
				header[index] = idx[1]
			}
			headers[i] = header
		case 2: // IPv6 + TCP
			header := make([]byte, ethernetIPv6TCPSize)
			copy(header, testIPv6TCPFrameHeader1)
			// random change data
			for j := 0; j < 2; j++ {
				_, err = rand.Read(idx)
				require.NoError(t, err)
				index := binary.BigEndian.Uint16(idx) % ethernetIPv6TCPSize
				header[index] = idx[1]
			}
			headers[i] = header
		case 3: // IPv6 + UDP
			header := make([]byte, ethernetIPv6UDPSize)
			copy(header, testIPv6UDPFrameHeader1)
			// random change data
			for j := 0; j < 1; j++ {
				_, err = rand.Read(idx)
				require.NoError(t, err)
				index := binary.BigEndian.Uint16(idx) % ethernetIPv6UDPSize
				header[index] = idx[1]
			}
			headers[i] = header
		case 4: // random length
			sizeBuf := make([]byte, 1)
			var size byte
			for size < 32 {
				_, err = rand.Read(sizeBuf)
				require.NoError(t, err)
				size = sizeBuf[0]
			}
			header := make([]byte, size)
			_, err = rand.Read(header)
			require.NoError(t, err)
			// at the end of the generated headers
			if i > len(headers)-10 {
				headers[i] = header
				continue
			}
			// append similar frame headers
			sHeader1 := make([]byte, size)
			copy(sHeader1, header)
			for j := 0; j < len(header)/minDiffDiv+2; j++ {
				sHeader1[j+10]++
			}
			sHeader2 := make([]byte, size)
			copy(sHeader2, header)
			for j := 0; j < len(header)/minDiffDiv+3; j++ {
				sHeader2[j+10]++
			}
			headers[i] = header
			headers[i+1] = sHeader1
			headers[i+2] = sHeader2
			i += 2
		}
	}
	return headers
}

func TestIsFrameHeaderPreferBeCompressed(t *testing.T) {
	t.Run("Ethernet IPv4 TCP", func(t *testing.T) {
		for _, header := range [][]byte{
			testIPv4TCPFrameHeader1,
			testIPv4TCPFrameHeader2,
			testIPv4TCPFrameHeader3,
			testIPv4TCPFrameHeader4,
			testIPv4TCPFrameHeader5,
			testIPv4TCPFrameHeader6,
			testIPv4TCPFrameHeader7,
			testIPv4TCPFrameHeader8,
		} {
			size, prefer := isFrameHeaderPreferBeCompressed(header)
			require.True(t, prefer)
			require.Equal(t, ethernetIPv4TCPSize, size)
		}
	})

	t.Run("Ethernet IPv4 UDP", func(t *testing.T) {
		for _, header := range [][]byte{
			testIPv4UDPFrameHeader1,
			testIPv4UDPFrameHeader2,
			testIPv4UDPFrameHeader3,
			testIPv4UDPFrameHeader4,
			testIPv4UDPFrameHeader5,
			testIPv4UDPFrameHeader6,
			testIPv4UDPFrameHeader7,
			testIPv4UDPFrameHeader8,
		} {
			size, prefer := isFrameHeaderPreferBeCompressed(header)
			require.True(t, prefer)
			require.Equal(t, ethernetIPv4UDPSize, size)
		}
	})

	t.Run("Ethernet IPv6 TCP", func(t *testing.T) {
		for _, header := range [][]byte{
			testIPv6TCPFrameHeader1,
			testIPv6TCPFrameHeader2,
			testIPv6TCPFrameHeader3,
			testIPv6TCPFrameHeader4,
			testIPv6TCPFrameHeader5,
			testIPv6TCPFrameHeader6,
			testIPv6TCPFrameHeader7,
			testIPv6TCPFrameHeader8,
		} {
			size, prefer := isFrameHeaderPreferBeCompressed(header)
			require.True(t, prefer)
			require.Equal(t, ethernetIPv6TCPSize, size)
		}
	})

	t.Run("Ethernet IPv6 UDP", func(t *testing.T) {
		for _, header := range [][]byte{
			testIPv6UDPFrameHeader1,
			testIPv6UDPFrameHeader2,
			testIPv6UDPFrameHeader3,
			testIPv6UDPFrameHeader4,
			testIPv6UDPFrameHeader5,
			testIPv6UDPFrameHeader6,
			testIPv6UDPFrameHeader7,
			testIPv6UDPFrameHeader8,
		} {
			size, prefer := isFrameHeaderPreferBeCompressed(header)
			require.True(t, prefer)
			require.Equal(t, ethernetIPv6UDPSize, size)
		}
	})

	t.Run("too small frame", func(t *testing.T) {
		size, prefer := isFrameHeaderPreferBeCompressed([]byte{})
		require.False(t, prefer)
		require.Zero(t, size)
	})

	t.Run("other network layer", func(t *testing.T) {
		header := make([]byte, len(testIPv4TCPFrameHeader1))
		copy(header, testIPv4TCPFrameHeader1)
		header[12] = 0xFF // next layer type
		header[13] = 0xFF // next layer type

		size, prefer := isFrameHeaderPreferBeCompressed(header)
		require.False(t, prefer)
		require.Zero(t, size)
	})

	t.Run("IPv4", func(t *testing.T) {
		t.Run("with options", func(t *testing.T) {
			header := make([]byte, len(testIPv4TCPFrameHeader1))
			copy(header, testIPv4TCPFrameHeader1)
			header[14] = 0x46 // header length is not 20

			size, prefer := isFrameHeaderPreferBeCompressed(header)
			require.False(t, prefer)
			require.Zero(t, size)
		})

		t.Run("other transport layer", func(t *testing.T) {
			header := make([]byte, len(testIPv4TCPFrameHeader1))
			copy(header, testIPv4TCPFrameHeader1)
			header[23] = 0xFF

			size, prefer := isFrameHeaderPreferBeCompressed(header)
			require.False(t, prefer)
			require.Zero(t, size)
		})

		t.Run("TCP", func(t *testing.T) {
			t.Run("invalid frame size", func(t *testing.T) {
				header := make([]byte, len(testIPv4TCPFrameHeader1)-1)
				copy(header, testIPv4TCPFrameHeader1)

				size, prefer := isFrameHeaderPreferBeCompressed(header)
				require.False(t, prefer)
				require.Zero(t, size)
			})

			t.Run("with options", func(t *testing.T) {
				header := make([]byte, len(testIPv4TCPFrameHeader1))
				copy(header, testIPv4TCPFrameHeader1)
				header[46] = 0xFF

				size, prefer := isFrameHeaderPreferBeCompressed(header)
				require.False(t, prefer)
				require.Zero(t, size)
			})
		})
	})

	t.Run("IPv6", func(t *testing.T) {
		t.Run("other transport layer", func(t *testing.T) {
			header := make([]byte, len(testIPv6TCPFrameHeader1))
			copy(header, testIPv6TCPFrameHeader1)
			header[20] = 0xFF

			size, prefer := isFrameHeaderPreferBeCompressed(header)
			require.False(t, prefer)
			require.Zero(t, size)
		})

		t.Run("TCP", func(t *testing.T) {
			t.Run("invalid frame size", func(t *testing.T) {
				header := make([]byte, len(testIPv6TCPFrameHeader1)-1)
				copy(header, testIPv6TCPFrameHeader1)

				size, prefer := isFrameHeaderPreferBeCompressed(header)
				require.False(t, prefer)
				require.Zero(t, size)
			})

			t.Run("with options", func(t *testing.T) {
				header := make([]byte, len(testIPv6TCPFrameHeader1))
				copy(header, testIPv6TCPFrameHeader1)
				header[66] = 0xFF

				size, prefer := isFrameHeaderPreferBeCompressed(header)
				require.False(t, prefer)
				require.Zero(t, size)
			})
		})

		t.Run("UDP", func(t *testing.T) {
			t.Run("invalid frame size", func(t *testing.T) {
				header := make([]byte, len(testIPv6UDPFrameHeader1)-1)
				copy(header, testIPv6UDPFrameHeader1)

				size, prefer := isFrameHeaderPreferBeCompressed(header)
				require.False(t, prefer)
				require.Zero(t, size)
			})
		})
	})
}

func TestIsFrameHeaderPreferBeCompressed_Fuzz(t *testing.T) {
	headers := testGenerateFrameHeaders(t)
	for _, header := range headers {
		f := append(header, 0)
		size, prefer := isFrameHeaderPreferBeCompressed(f)
		if !prefer {
			continue
		}
		switch size {
		case ethernetIPv4TCPSize:
		case ethernetIPv4UDPSize:
		case ethernetIPv6TCPSize:
		case ethernetIPv6UDPSize:
		default:
			t.Fatalf("invalid size: %d", size)
		}
	}
}

func BenchmarkIsFrameHeaderPreferBeCompressed(b *testing.B) {
	b.Run("Ethernet IPv4 TCP", benchmarkIsFrameHeaderPreferBeCompressedEthernetIPv4TCP)
	b.Run("Ethernet IPv4 UDP", benchmarkIsFrameHeaderPreferBeCompressedEthernetIPv4UDP)
	b.Run("Ethernet IPv6 TCP", benchmarkIsFrameHeaderPreferBeCompressedEthernetIPv6TCP)
	b.Run("Ethernet IPv6 UDP", benchmarkIsFrameHeaderPreferBeCompressedEthernetIPv6UDP)
}

func benchmarkIsFrameHeaderPreferBeCompressedEthernetIPv4TCP(b *testing.B) {
	header := make([]byte, len(testIPv4TCPFrameHeader1)+16)
	copy(header, testIPv4TCPFrameHeader1)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		size, prefer := isFrameHeaderPreferBeCompressed(header)
		if !prefer {
			b.Fatal("not prefer")
		}
		if size != ethernetIPv4TCPSize {
			b.Fatal("invalid size")
		}
	}

	b.StopTimer()
}

func benchmarkIsFrameHeaderPreferBeCompressedEthernetIPv4UDP(b *testing.B) {
	header := make([]byte, len(testIPv4UDPFrameHeader1)+16)
	copy(header, testIPv4UDPFrameHeader1)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		size, prefer := isFrameHeaderPreferBeCompressed(header)
		if !prefer {
			b.Fatal("not prefer")
		}
		if size != ethernetIPv4UDPSize {
			b.Fatal("invalid size")
		}
	}

	b.StopTimer()
}

func benchmarkIsFrameHeaderPreferBeCompressedEthernetIPv6TCP(b *testing.B) {
	header := make([]byte, len(testIPv6TCPFrameHeader1)+16)
	copy(header, testIPv6TCPFrameHeader1)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		size, prefer := isFrameHeaderPreferBeCompressed(header)
		if !prefer {
			b.Fatal("not prefer")
		}
		if size != ethernetIPv6TCPSize {
			b.Fatal("invalid size")
		}
	}

	b.StopTimer()
}

func benchmarkIsFrameHeaderPreferBeCompressedEthernetIPv6UDP(b *testing.B) {
	header := make([]byte, len(testIPv6UDPFrameHeader1)+16)
	copy(header, testIPv6UDPFrameHeader1)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		size, prefer := isFrameHeaderPreferBeCompressed(header)
		if !prefer {
			b.Fatal("not prefer")
		}
		if size != ethernetIPv6UDPSize {
			b.Fatal("invalid size")
		}
	}

	b.StopTimer()
}
