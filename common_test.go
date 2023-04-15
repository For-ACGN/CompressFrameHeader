package cfh

import (
	"encoding/hex"
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
