// Package probe implements the small subset of ping, traceroute, and mtr used
// by the agent. It requires CAP_NET_RAW for ICMP replies. Traceroute uses UDP
// probes with a stable source/destination port pair for each sampled flow.
package probe

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"strings"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

const (
	maxTraceHops = 24
	traceFlows   = 3
	traceWait    = 800 * time.Millisecond
	mtrHops      = 20
	mtrWait      = 350 * time.Millisecond
)

type target struct {
	ip    net.IP
	v6    bool
	proto int
}

func resolve(ctx context.Context, host, family string) (target, error) {
	if ip := net.ParseIP(host); ip != nil {
		if family == "ipv6" && ip.To4() != nil || family != "ipv6" && ip.To4() == nil {
			return target{}, fmt.Errorf("%s is not a %s address", host, family)
		}
		return target{ip: ip, v6: ip.To4() == nil, proto: protocol(ip)}, nil
	}
	network := "ip4"
	if family == "ipv6" {
		network = "ip6"
	}
	addresses, err := net.DefaultResolver.LookupIP(ctx, network, host)
	if err != nil {
		return target{}, fmt.Errorf("resolve %s: %w", host, err)
	}
	if len(addresses) == 0 {
		return target{}, fmt.Errorf("resolve %s: no %s address", host, network)
	}
	return target{ip: addresses[0], v6: network == "ip6", proto: protocol(addresses[0])}, nil
}

func protocol(ip net.IP) int {
	if ip.To4() != nil {
		return 1
	}
	return 58
}

func listen(t target) (*icmp.PacketConn, error) {
	if t.v6 {
		return icmp.ListenPacket("ip6:ipv6-icmp", "::")
	}
	return icmp.ListenPacket("ip4:icmp", "0.0.0.0")
}

// Run executes the built-in implementation. The caller owns output limits and
// job timeouts. The target has already passed the agent's private-IP guard.
func Run(ctx context.Context, tool, host, family string, count int, out io.Writer) error {
	t, err := resolve(ctx, host, family)
	if err != nil {
		return err
	}
	switch tool {
	case "ping":
		return ping(ctx, t, count, out)
	case "traceroute":
		return traceroute(ctx, t, out)
	case "mtr":
		return mtr(ctx, t, out)
	default:
		return fmt.Errorf("no built-in probe for %s", tool)
	}
}

func ping(ctx context.Context, t target, count int, out io.Writer) error {
	conn, err := listen(t)
	if err != nil {
		return fmt.Errorf("icmp socket: %w", err)
	}
	defer conn.Close()
	if count != 10 {
		count = 5
	}
	// Read the received TTL from the IP control message, like iputils prints it.
	if t.v6 {
		_ = conn.IPv6PacketConn().SetControlMessage(ipv6.FlagHopLimit, true)
	} else {
		_ = conn.IPv4PacketConn().SetControlMessage(ipv4.FlagTTL, true)
	}

	const payloadSize = 56
	payload := make([]byte, payloadSize)
	copy(payload, "hlg-probe")
	// Match iputils -O: "PING <host> (<ip>) 56(84) bytes of data." (v4) or
	// "PING <host>(<ip>) 56 data bytes" (v6).
	header := fmt.Sprintf("(built-in) PING %s (%s) %d(%d) bytes of data.", t.ip, t.ip, payloadSize, payloadSize+8+20)
	if t.v6 {
		header = fmt.Sprintf("(built-in) PING %s(%s) %d data bytes", t.ip, t.ip, payloadSize)
	}
	if _, err := fmt.Fprintln(out, header); err != nil {
		return err
	}
	id := os.Getpid() & 0xffff
	received := 0
	var min, max, sum, sumsq time.Duration
	startedAt := time.Now()
	for seq := 1; seq <= count; seq++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		reply, ttl, rtt, err := pingOnce(ctx, conn, t, id, seq, payload)
		if err != nil {
			return err
		}
		if reply == "" {
			if _, err := fmt.Fprintf(out, "no answer yet for icmp_seq=%d\n", seq); err != nil {
				return err
			}
		} else {
			received++
			if received == 1 || rtt < min {
				min = rtt
			}
			if rtt > max {
				max = rtt
			}
			sum += rtt
			sumsq += rtt * rtt
			if _, err := fmt.Fprintf(out, "64 bytes from %s: icmp_seq=%d ttl=%d time=%s ms\n", reply, seq, ttl, millis(rtt)); err != nil {
				return err
			}
		}
		if seq < count {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(time.Until(startedAt.Add(time.Duration(seq) * time.Second))):
			}
		}
	}
	elapsed := time.Since(startedAt)
	if _, err := fmt.Fprintf(out, "\n--- %s ping statistics ---\n", t.ip); err != nil {
		return err
	}
	loss := float64(count-received) * 100 / float64(count)
	if _, err := fmt.Fprintf(out, "%d packets transmitted, %d received, %s%% packet loss, time %dms\n", count, received, trimFloat(loss), elapsed.Milliseconds()); err != nil {
		return err
	}
	if received > 0 {
		avg := sum / time.Duration(received)
		mean := sumsq / time.Duration(received)
		variance := float64(mean) - float64(avg)*float64(avg)
		mdev := time.Duration(0)
		if variance > 0 {
			mdev = time.Duration(math.Sqrt(variance))
		}
		if _, err := fmt.Fprintf(out, "rtt min/avg/max/mdev = %s/%s/%s/%s ms\n", millis(min), millis(avg), millis(max), millis(mdev)); err != nil {
			return err
		}
	}
	return nil
}

// pingOnce sends one echo request and waits up to 2s for the matching reply,
// returning the responder, the reply TTL, and the RTT ("" responder = no reply).
func pingOnce(ctx context.Context, conn *icmp.PacketConn, t target, id, seq int, payload []byte) (string, int, time.Duration, error) {
	var typ icmp.Type = ipv4.ICMPTypeEcho
	if t.v6 {
		typ = ipv6.ICMPTypeEchoRequest
	}
	packet, err := (&icmp.Message{Type: typ, Code: 0, Body: &icmp.Echo{ID: id, Seq: seq, Data: payload}}).Marshal(nil)
	if err != nil {
		return "", 0, 0, err
	}
	started := time.Now()
	if _, err := conn.WriteTo(packet, &net.IPAddr{IP: t.ip}); err != nil {
		return "", 0, 0, err
	}
	deadline := started.Add(2 * time.Second)
	buf := make([]byte, 2048)
	for time.Now().Before(deadline) {
		if err := ctx.Err(); err != nil {
			return "", 0, 0, err
		}
		_ = conn.SetReadDeadline(minTime(deadline, time.Now().Add(100*time.Millisecond)))
		var (
			n    int
			from net.Addr
			ttl  int
		)
		if t.v6 {
			var cm *ipv6.ControlMessage
			n, cm, from, err = conn.IPv6PacketConn().ReadFrom(buf)
			if cm != nil {
				ttl = cm.HopLimit
			}
		} else {
			var cm *ipv4.ControlMessage
			n, cm, from, err = conn.IPv4PacketConn().ReadFrom(buf)
			if cm != nil {
				ttl = cm.TTL
			}
		}
		if isTimeout(err) {
			continue
		}
		if err != nil {
			return "", 0, 0, err
		}
		message, err := icmp.ParseMessage(t.proto, buf[:n])
		if err != nil || message.Type != echoReplyType(t.v6) {
			continue
		}
		echo, ok := message.Body.(*icmp.Echo)
		if !ok || echo.ID != id || echo.Seq != seq {
			continue
		}
		return address(from), ttl, time.Since(started), nil
	}
	return "", 0, 0, nil
}

// millis formats a duration as iputils does: seconds with 3 decimals.
func millis(d time.Duration) string {
	return fmt.Sprintf("%.3f", ms(d))
}

// trimFloat drops a trailing ".0" so "0.0" prints as "0", like iputils.
func trimFloat(v float64) string {
	s := fmt.Sprintf("%.1f", v)
	return strings.TrimSuffix(s, ".0")
}

func echoReplyType(v6 bool) icmp.Type {
	if v6 {
		return ipv6.ICMPTypeEchoReply
	}
	return ipv4.ICMPTypeEchoReply
}

type hopReply struct {
	address string
	rtt     time.Duration
	reached bool
	labels  []icmp.MPLSLabel
}

type traceSocket struct {
	conn    *net.UDPConn
	srcPort int
	dstPort int
	reached bool
}

func openFlows(t target, count int) ([]traceSocket, error) {
	flows := make([]traceSocket, 0, count)
	for i := 0; i < count; i++ {
		addr := &net.UDPAddr{IP: net.IPv4zero}
		network := "udp4"
		if t.v6 {
			addr.IP = net.IPv6zero
			network = "udp6"
		}
		conn, err := net.ListenUDP(network, addr)
		if err != nil {
			closeFlows(flows)
			return nil, err
		}
		flows = append(flows, traceSocket{conn: conn, srcPort: conn.LocalAddr().(*net.UDPAddr).Port, dstPort: 33434 + i})
	}
	return flows, nil
}

func closeFlows(flows []traceSocket) {
	for _, flow := range flows {
		_ = flow.conn.Close()
	}
}

func setHopLimit(conn *net.UDPConn, v6 bool, ttl int) error {
	if v6 {
		return ipv6.NewPacketConn(conn).SetHopLimit(ttl)
	}
	return ipv4.NewPacketConn(conn).SetTTL(ttl)
}

func traceHop(ctx context.Context, t target, recv *icmp.PacketConn, flows []traceSocket, ttl int, wait time.Duration) ([]*hopReply, error) {
	replies := make([]*hopReply, len(flows))
	started := make([]time.Time, len(flows))
	pending := 0
	for i := range flows {
		if flows[i].reached {
			continue
		}
		if err := setHopLimit(flows[i].conn, t.v6, ttl); err != nil {
			return nil, err
		}
		started[i] = time.Now()
		// Constant payload and ports keep the flow hash stable across TTLs.
		if _, err := flows[i].conn.WriteToUDP([]byte("hlg-probe"), &net.UDPAddr{IP: t.ip, Port: flows[i].dstPort}); err != nil {
			return nil, err
		}
		pending++
	}
	deadline := time.Now().Add(wait)
	buf := make([]byte, 4096)
	for pending > 0 && time.Now().Before(deadline) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		_ = recv.SetReadDeadline(minTime(deadline, time.Now().Add(100*time.Millisecond)))
		n, from, err := recv.ReadFrom(buf)
		if isTimeout(err) {
			continue
		}
		if err != nil {
			return nil, err
		}
		message, err := icmp.ParseMessage(t.proto, buf[:n])
		if err != nil {
			continue
		}
		quoted, reached, labels := quotedUDP(message, t.v6)
		if len(quoted) == 0 {
			continue
		}
		src, dst, ok := udpPorts(quoted, t.v6)
		if !ok {
			continue
		}
		for i := range flows {
			if replies[i] != nil || flows[i].reached || flows[i].srcPort != src || flows[i].dstPort != dst {
				continue
			}
			replies[i] = &hopReply{address: address(from), rtt: time.Since(started[i]), reached: reached, labels: labels}
			flows[i].reached = reached
			pending--
			break
		}
	}
	return replies, nil
}

func quotedUDP(message *icmp.Message, v6 bool) ([]byte, bool, []icmp.MPLSLabel) {
	var data []byte
	var extensions []icmp.Extension
	reached := false
	switch body := message.Body.(type) {
	case *icmp.TimeExceeded:
		data, extensions = body.Data, body.Extensions
	case *icmp.DstUnreach:
		data, extensions = body.Data, body.Extensions
		reached = message.Code == 3 && !v6 || message.Code == 4 && v6
	default:
		return nil, false, nil
	}
	var labels []icmp.MPLSLabel
	for _, extension := range extensions {
		if stack, ok := extension.(*icmp.MPLSLabelStack); ok {
			labels = append(labels, stack.Labels...)
		}
	}
	return data, reached, labels
}

func udpPorts(packet []byte, v6 bool) (int, int, bool) {
	offset := 0
	if v6 {
		if len(packet) < 48 || packet[0]>>4 != 6 || packet[6] != 17 {
			return 0, 0, false
		}
		offset = 40
	} else {
		if len(packet) < 28 || packet[0]>>4 != 4 || packet[9] != 17 {
			return 0, 0, false
		}
		offset = int(packet[0]&0xf) * 4
		if offset < 20 || len(packet) < offset+8 {
			return 0, 0, false
		}
	}
	return int(packet[offset])<<8 | int(packet[offset+1]), int(packet[offset+2])<<8 | int(packet[offset+3]), true
}

func traceroute(ctx context.Context, t target, out io.Writer) error {
	recv, err := listen(t)
	if err != nil {
		return fmt.Errorf("icmp socket: %w", err)
	}
	defer recv.Close()
	flows, err := openFlows(t, traceFlows)
	if err != nil {
		return err
	}
	defer closeFlows(flows)
	if _, err := fmt.Fprintf(out, "(built-in) traceroute to %s (%s), %d hops max, 60 byte packets\n", t.ip, t.ip, maxTraceHops); err != nil {
		return err
	}
	for ttl := 1; ttl <= maxTraceHops; ttl++ {
		replies, err := traceHop(ctx, t, recv, flows, ttl, traceWait)
		if err != nil {
			return err
		}
		// Group the (up to three) probes of this TTL by responder, keeping every
		// RTT — official traceroute prints one line per responder with its probe
		// times. More than one responder is an ECMP split.
		type responder struct {
			times  []time.Duration
			labels []icmp.MPLSLabel
		}
		byHost := map[string]*responder{}
		order := []string{}
		unanswered := false
		for _, reply := range replies {
			if reply == nil {
				unanswered = true
				continue
			}
			entry, ok := byHost[reply.address]
			if !ok {
				entry = &responder{}
				byHost[reply.address] = entry
				order = append(order, reply.address)
			}
			entry.times = append(entry.times, reply.rtt)
			if len(reply.labels) > 0 && len(entry.labels) == 0 {
				entry.labels = reply.labels
			}
		}
		ecmp := len(order) > 1
		if len(order) == 0 {
			if _, err := fmt.Fprintf(out, "%2d  *\n", ttl); err != nil {
				return err
			}
		} else {
			for i, host := range order {
				entry := byHost[host]
				prefix := "    "
				if i == 0 {
					prefix = fmt.Sprintf("%2d  ", ttl)
				}
				times := make([]string, len(entry.times))
				for j, rtt := range entry.times {
					times[j] = millis(rtt) + " ms"
				}
				mark := ""
				if ecmp {
					mark += " [ECMP]"
				}
				mark += formatLabels(entry.labels)
				if _, err := fmt.Fprintf(out, "%s%s %s%s\n", prefix, host, strings.Join(times, " "), mark); err != nil {
					return err
				}
			}
			if unanswered && !ecmp {
				if _, err := fmt.Fprintf(out, "    *\n"); err != nil {
					return err
				}
			}
		}
		allReached := true
		for _, flow := range flows {
			if !flow.reached {
				allReached = false
				break
			}
		}
		if allReached {
			return nil
		}
	}
	return nil
}

// formatLabels renders MPLS labels the way traceroute marks them.
func formatLabels(labels []icmp.MPLSLabel) string {
	if len(labels) == 0 {
		return ""
	}
	parts := make([]string, 0, len(labels))
	for _, label := range labels {
		parts = append(parts, fmt.Sprintf("%d/TC%d/TTL%d", label.Label, label.TC, label.TTL))
	}
	return " [MPLS " + strings.Join(parts, ",") + "]"
}

type hopStats struct {
	host     string
	sent     int
	received int
	last     float64
	sum      float64
	best     float64
	worst    float64
}

func (s *hopStats) update(reply *hopReply) {
	s.sent++
	if reply == nil {
		return
	}
	s.host = reply.address
	rtt := ms(reply.rtt)
	s.last = rtt
	s.sum += rtt
	if s.received == 0 || rtt < s.best {
		s.best = rtt
	}
	if rtt > s.worst {
		s.worst = rtt
	}
	s.received++
}

func (s hopStats) line(hop int) string {
	host := s.host
	if host == "" {
		host = "???"
	}
	loss := 0.0
	if s.sent > 0 {
		loss = 100 * float64(s.sent-s.received) / float64(s.sent)
	}
	avg := 0.0
	if s.received > 0 {
		avg = s.sum / float64(s.received)
	}
	return fmt.Sprintf("%d %s %.1f%% %d %.3f %.3f %.3f %.3f", hop, host, loss, s.sent, s.last, avg, s.best, s.worst)
}

func mtr(ctx context.Context, t target, out io.Writer) error {
	recv, err := listen(t)
	if err != nil {
		return fmt.Errorf("icmp socket: %w", err)
	}
	defer recv.Close()
	flows, err := openFlows(t, 1)
	if err != nil {
		return err
	}
	defer closeFlows(flows)
	stats := make([]hopStats, mtrHops)
	if _, err := fmt.Fprintf(out, "(built-in) mtr to %s\n", t.ip); err != nil {
		return err
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		flows[0].reached = false
		for ttl := 1; ttl <= mtrHops; ttl++ {
			replies, err := traceHop(ctx, t, recv, flows, ttl, mtrWait)
			if err != nil {
				return err
			}
			stats[ttl-1].update(replies[0])
			if _, err := fmt.Fprintln(out, stats[ttl-1].line(ttl)); err != nil {
				return err
			}
			if flows[0].reached {
				break
			}
		}
	}
}

func address(addr net.Addr) string {
	if ip, ok := addr.(*net.IPAddr); ok {
		return ip.IP.String()
	}
	return addr.String()
}

func isTimeout(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

func ms(d time.Duration) float64 { return math.Round(float64(d)/float64(time.Microsecond)) / 1000 }
