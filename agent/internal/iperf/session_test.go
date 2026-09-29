package iperf

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestConfirmListenDoesNotConnectToSingleUseServer(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	accepted := make(chan struct{}, 1)
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			_ = conn.Close()
			accepted <- struct{}{}
		}
	}()

	port := listener.Addr().(*net.TCPAddr).Port
	if err := confirmListen(context.Background(), port); err != nil {
		t.Fatal(err)
	}

	select {
	case <-accepted:
		t.Fatal("confirmListen opened a TCP connection")
	case <-time.After(100 * time.Millisecond):
	}
}
