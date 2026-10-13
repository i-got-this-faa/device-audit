package mesh

import (
	"errors"
	"testing"
)

func TestDevelopmentBindingAndUnimplementedMesh(t *testing.T) {
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
	if _, err := NewServer(ServerConfig{}); !errors.Is(err, ErrNotImplemented) {
		t.Fatalf("server error: %v", err)
	}
	if _, err := NewClient(ClientConfig{}); !errors.Is(err, ErrNotImplemented) {
		t.Fatalf("client error: %v", err)
	}
}
