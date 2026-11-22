package mesh

import (
	"errors"
	"testing"
	"time"
)

func TestDevelopmentBindingAndInvalidMesh(t *testing.T) {
	for _, address := range []string{":8080", "0.0.0.0:8080", "192.0.2.1:8080", "example.com:8080"} {
		if listener, err := ListenLocal(address); err == nil {
			listener.Close()
			t.Fatalf("accepted non-loopback %s", address)
		}
	}
	listener, err := ListenLocal("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listener.Close()
	if _, err := NewServer(ServerConfig{}); err == nil {
		t.Fatalf("server error: %v", err)
	}
	if _, err := NewClient(ClientConfig{}); err == nil {
		t.Fatalf("client error: %v", err)
	}
}

func TestBoundedCloseReturnsWhenTeardownHangs(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	start := time.Now()
	err := boundedClose(func() error { <-release; return nil }, 50*time.Millisecond)
	if !errors.Is(err, ErrCloseTimeout) || time.Since(start) > 2*time.Second {
		t.Fatalf("hung teardown: err=%v after %s", err, time.Since(start))
	}
	closed := errors.New("closed")
	if err := boundedClose(func() error { return closed }, time.Second); !errors.Is(err, closed) {
		t.Fatalf("prompt teardown error lost: %v", err)
	}
}
