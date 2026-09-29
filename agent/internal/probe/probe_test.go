package probe

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

func TestQuotedUDPAndMPLS(t *testing.T) {
	packet := make([]byte, 28)
	packet[0] = 0x45
	packet[9] = 17
	binary.BigEndian.PutUint16(packet[20:22], 41000)
	binary.BigEndian.PutUint16(packet[22:24], 33434)
	stack := &icmp.MPLSLabelStack{Labels: []icmp.MPLSLabel{{Label: 16001, TC: 3, TTL: 250}}}
	msg := &icmp.Message{Type: ipv4.ICMPTypeTimeExceeded, Body: &icmp.TimeExceeded{Data: packet, Extensions: []icmp.Extension{stack}}}
	quoted, reached, labels := quotedUDP(msg, false)
	if reached || len(labels) != 1 || labels[0].Label != 16001 {
		t.Fatalf("unexpected reply: reached=%v labels=%+v", reached, labels)
	}
	src, dst, ok := udpPorts(quoted, false)
	if !ok || src != 41000 || dst != 33434 {
		t.Fatalf("wrong ports: %d %d %v", src, dst, ok)
	}
	if got := formatLabels(labels); !strings.Contains(got, "16001/TC3/TTL250") {
		t.Fatalf("missing MPLS label: %q", got)
	}
	msg.Type = ipv4.ICMPTypeDestinationUnreachable
	msg.Code = 3
	msg.Body = &icmp.DstUnreach{Data: packet}
	_, reached, _ = quotedUDP(msg, false)
	if !reached {
		t.Fatal("port unreachable should mark the flow reached")
	}
}

func TestUDPPortsRejectMalformed(t *testing.T) {
	for _, packet := range [][]byte{nil, make([]byte, 27), append([]byte{0x45}, make([]byte, 27)...)} {
		if _, _, ok := udpPorts(packet, false); ok {
			t.Fatalf("accepted malformed IPv4 quote: %v", packet)
		}
	}
	v6 := make([]byte, 48)
	v6[0], v6[6] = 0x60, 17
	binary.BigEndian.PutUint16(v6[40:42], 41000)
	binary.BigEndian.PutUint16(v6[42:44], 33434)
	if src, dst, ok := udpPorts(v6, true); !ok || src != 41000 || dst != 33434 {
		t.Fatalf("IPv6 quote: %d %d %v", src, dst, ok)
	}
}

func TestHopStatsMatchesMTRColumns(t *testing.T) {
	var stats hopStats
	stats.update(nil)
	stats.update(&hopReply{address: net.IPv4(192, 0, 2, 1).String(), rtt: 2 * time.Millisecond})
	if got := stats.line(3); got != "3 192.0.2.1 50.0% 2 2.000 2.000 2.000 2.000" {
		t.Fatalf("unexpected split row: %q", got)
	}
}

func TestPingLoopbackIntegration(t *testing.T) {
	if os.Getenv("HLG_PROBE_INTEGRATION") != "1" {
		t.Skip("set HLG_PROBE_INTEGRATION=1 to exercise the raw ICMP socket")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	var out bytes.Buffer
	err := Run(ctx, "ping", "127.0.0.1", "ipv4", 5, &out)
	if err != nil && !strings.Contains(err.Error(), "context deadline exceeded") {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "icmp_seq=1 time=") {
		t.Fatalf("no loopback reply: %q", out.String())
	}
}

func TestTraceLoopbackIntegration(t *testing.T) {
	if os.Getenv("HLG_PROBE_INTEGRATION") != "1" {
		t.Skip("set HLG_PROBE_INTEGRATION=1 to exercise raw ICMP sockets")
	}
	var trace bytes.Buffer
	if err := Run(context.Background(), "traceroute", "127.0.0.1", "ipv4", 0, &trace); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(trace.String(), "traceroute to 127.0.0.1") || !strings.Contains(trace.String(), "1  127.0.0.1") {
		t.Fatalf("no traced loopback flow: %q", trace.String())
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	var report bytes.Buffer
	_ = Run(ctx, "mtr", "127.0.0.1", "ipv4", 0, &report)
	if !strings.Contains(report.String(), "1 127.0.0.1") {
		t.Fatalf("no mtr loopback row: %q", report.String())
	}
}
