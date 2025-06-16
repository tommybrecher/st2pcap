package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

func parseLogLine(line string) (srcIP, dstIP net.IP, srcPort, dstPort int, sipMsg []byte, ok bool) {
	parts := strings.Split(line, "|")
	if len(parts) < 11 {
		return nil, nil, 0, 0, nil, false
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
		return nil, nil, 0, 0, nil, false
	}
	var err error
	srcPort, err = parseInt(parts[6])
	if err != nil {
		return nil, nil, 0, 0, nil, false
	}
	dstPort, err = parseInt(parts[9])
	if err != nil {
		return nil, nil, 0, 0, nil, false
	}
	return srcIP, dstIP, srcPort, dstPort, sipMsg, true
}

func parseInt(s string) (int, error) {
	return fmt.Sscanf(s, "%d", new(int))
}

func main() {
	input := flag.String("input", "", "Input SIP log file (SIPTrace format)")
	output := flag.String("output", "", "Output PCAP file")
	flag.Parse()
	if *input == "" {
		log.Fatal("Input file required")
	}
	inFile, err := os.Open(*input)
	if err != nil {
		log.Fatalf("Failed to open input: %v", err)
	}
	defer inFile.Close()
	outFile, err := os.Create(*output)
	if err != nil {
		log.Fatalf("Failed to create output: %v", err)
	}
	defer outFile.Close()
	writer := pcapgo.NewWriter(outFile)
	writer.WriteFileHeader(65535, layers.LinkTypeEthernet)
	scanner := bufio.NewScanner(inFile)
	for scanner.Scan() {
		line := scanner.Text()
		srcIP, dstIP, srcPort, dstPort, data, ok := parseLogLine(line)
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
		ts := time.Now()
		writer.WritePacket(gopacket.CaptureInfo{Timestamp: ts, Length: len(buffer.Bytes()), CaptureLength: len(buffer.Bytes())}, buffer.Bytes())
	}
	if err := scanner.Err(); err != nil {
		log.Fatalf("Scan error: %v", err)
	}
}
