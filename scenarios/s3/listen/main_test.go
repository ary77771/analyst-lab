package main

import (
	"net"
	"testing"
	"time"
)

func freeLoopback(t *testing.T) string {
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	return addr
}

func TestPortIsOpenWhileHeldAndClosedAfter(t *testing.T) {
	addr := freeLoopback(t)
	held := make(chan struct{})
	release := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- run(addr, time.Minute, func(time.Duration) { close(held); <-release })
	}()
	<-held
	// while held: the port is taken (a second listener can't bind it)
	if l, err := net.Listen("tcp4", addr); err == nil {
		l.Close()
		t.Fatal("port was not held")
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	// afterwards: free again
	l, err := net.Listen("tcp4", addr)
	if err != nil {
		t.Fatalf("port still taken after the scenario: %v", err)
	}
	l.Close()
}

func TestOnlyLoopbackIsAllowed(t *testing.T) {
	for _, addr := range []string{"0.0.0.0:47213", "10.0.2.15:47213", ":47213", "example.com:80", "nonsense"} {
		if err := run(addr, time.Second, func(time.Duration) {}); err == nil {
			t.Fatalf("%s was accepted", addr)
		}
	}
}

func TestHoldMustBePositive(t *testing.T) {
	if err := run(freeLoopback(t), 0, func(time.Duration) {}); err == nil {
		t.Fatal("hold 0 accepted")
	}
}
