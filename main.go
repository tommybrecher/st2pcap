package main

import (
	"bufio"
	"flag"
	"log"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

func parseLogLine(line string) (srcIP, dstIP net.IP, srcPort, dstPort int, sipMsg []byte, pktTime time.Time, ok bool) {
	parts := strings.Split(line, "|")
	if len(parts) < 11 {
		return nil, nil, 0, 0, nil, time.Time{}, false
	}
	// The SIP message is before the first pipe
	sipMsgStr := parts[0]
	// Replace \\x0D\\x0A with CRLF
	re := regexp.MustCompile(`\\x0D\\x0A`)
	sipMsgStr = re.ReplaceAllString(sipMsgStr, "\r\n")
	// Ensure SIP message ends with double CRLF
	if !strings.HasSuffix(sipMsgStr, "\r\n\r\n") {
		if strings.HasSuffix(sipMsgStr, "\r\n") {
			sipMsgStr += "\r\n"
		} else {
			sipMsgStr += "\r\n\r\n"
		}
	}
	sipMsg = []byte(sipMsgStr)
	// Extract network info from metadata
	srcIP = net.ParseIP(parts[5]).To4()
	dstIP = net.ParseIP(parts[8]).To4()
	if srcIP == nil || dstIP == nil {
		return nil, nil, 0, 0, nil, time.Time{}, false
	}
	var err error
	srcPort, err = parseInt(parts[6])
	if err != nil {
		return nil, nil, 0, 0, nil, time.Time{}, false
	}
	dstPort, err = parseInt(parts[9])
	if err != nil {
		return nil, nil, 0, 0, nil, time.Time{}, false
	}
	// Parse timestamp (field 10) with sub-second precision
	tsFloat, err := strconv.ParseFloat(parts[10], 64)
	if err != nil {
		return nil, nil, 0, 0, nil, time.Time{}, false
	}
	sec := int64(tsFloat)
	nsec := int64((tsFloat - float64(sec)) * 1e9)
	pktTime = time.Unix(sec, nsec)
	return srcIP, dstIP, srcPort, dstPort, sipMsg, pktTime, true
}

func parseInt(s string) (int, error) {
	return strconv.Atoi(s)
}

func main() {
	var input, output string
	flag.StringVar(&input, "input", "", "Input SIP log file (SIPTrace format)")
	flag.StringVar(&input, "i", "", "Input SIP log file (SIPTrace format)")
	flag.StringVar(&output, "output", "", "Output PCAP file")
	flag.StringVar(&output, "o", "", "Output PCAP file")
	flag.Parse()
	if flag.NFlag() == 0 {
		log.Println("Usage: st2pcap -i, -input <inputfile> [-o, -output <outputfile>]")
		log.Fatal("No arguments provided")
	}
	if input == "" {
		log.Fatal("Input file required")
	}
	// Default output filename if not provided, strip extension
	if output == "" {
		base := filepath.Base(input)
		ext := filepath.Ext(base)
		output = strings.TrimSuffix(base, ext) + ".pcap"
	}
	inFile, err := os.Open(input)
	if err != nil {
		log.Fatalf("Failed to open input: %v", err)
	}
	defer inFile.Close()
	outFile, err := os.Create(output)
	if err != nil {
		log.Fatalf("Failed to create output: %v", err)
	}
	defer outFile.Close()
	writer := pcapgo.NewWriter(outFile)
	writer.WriteFileHeader(65535, layers.LinkTypeEthernet)
	scanner := bufio.NewScanner(inFile)
	for scanner.Scan() {
		line := scanner.Text()
		srcIP, dstIP, srcPort, dstPort, data, pktTime, ok := parseLogLine(line)
		if !ok {
			continue
		}
		// Force SIP port 5060 for Wireshark detection if either port is 5060
		if srcPort != 5060 && dstPort != 5060 {
			dstPort = 5060
		}
		udp := &layers.UDP{
			SrcPort: layers.UDPPort(srcPort),
			DstPort: layers.UDPPort(dstPort),
		}
		udp.SetNetworkLayerForChecksum(&layers.IPv4{SrcIP: srcIP, DstIP: dstIP})
		ip := &layers.IPv4{
			Version:  4,
			IHL:      5,
			TTL:      64,
			Protocol: layers.IPProtocolUDP,
			SrcIP:    srcIP,
			DstIP:    dstIP,
		}
		eth := &layers.Ethernet{
			SrcMAC:       net.HardwareAddr{0x00, 0x01, 0x02, 0x03, 0x04, 0x05},
			DstMAC:       net.HardwareAddr{0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b},
			EthernetType: layers.EthernetTypeIPv4,
		}
		buffer := gopacket.NewSerializeBuffer()
		opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
		err = gopacket.SerializeLayers(buffer, opts, eth, ip, udp, gopacket.Payload(data))
		if err != nil {
			log.Printf("Failed to serialize packet: %v", err)
			continue
		}
		writer.WritePacket(gopacket.CaptureInfo{Timestamp: pktTime, Length: len(buffer.Bytes()), CaptureLength: len(buffer.Bytes())}, buffer.Bytes())
	}
	if err := scanner.Err(); err != nil {
		log.Fatalf("Scan error: %v", err)
	}
}
