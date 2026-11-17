// Command relay runs the scoped self-hosted DERP relay for one deployment.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/i-got-this-faa/device-audit/networking/mesh"
	"github.com/i-got-this-faa/device-audit/networking/relay"
)

func main() {
	if err := run(context.Background(), os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "relay:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("relay", flag.ContinueOnError)
	initKey := flags.Bool("init-key", false, "exclusively create the relay key file and exit")
	printRegion := flags.Bool("print-region", false, "print the mesh DERP region JSON for this relay and exit")
	keyFile := flags.String("key-file", "", "private relay DERP key file, mode 0600")
	listen := flags.String("listen", ":443", "TLS DERP listen address")
	hostname := flags.String("hostname", "", "relay DNS name covered by the selected certificate")
	certFile := flags.String("tls-cert", "", "selected PEM certificate chain")
	tlsKey := flags.String("tls-key", "", "PEM private key for --tls-cert")
	admission := flags.String("admission-file", "", "relay admission JSON of admitted mesh network public keys")
	regionID := flags.Int("region-id", 900, "DERP region ID for --print-region")
	port := flags.Int("port", 443, "advertised DERP TCP port for --print-region")
	ipv4 := flags.String("ipv4", "", "optional advertised IPv4 dial address for --print-region")
	certName := flags.String("cert-name", "", "optional certificate pin for --print-region, such as sha256-raw:<hex>")
	if err := flags.Parse(args); err != nil {
		return err
	}
	switch {
	case *initKey:
		if *keyFile == "" {
			return errors.New("--init-key requires --key-file")
		}
		return relay.InitializeNodeKey(*keyFile)
	case *printRegion:
		region := relay.Region(*regionID, *hostname, *ipv4, *port, *certName)
		data, err := json.MarshalIndent(region, "", "  ")
		if err != nil {
			return err
		}
		// Reject anything the mesh adapter would reject before it is distributed.
		if _, err := mesh.DecodeRegion(data); err != nil || net.ParseIP(*hostname) != nil {
			return errors.New("region would be rejected by the mesh adapter; supply a DNS --hostname and valid --port/--region-id")
		}
		_, err = fmt.Fprintln(stdout, string(data))
		return err
	}
	r, err := relay.New(relay.Config{Hostname: *hostname, CertFile: *certFile, KeyFile: *tlsKey, NodeKeyFile: *keyFile, AdmissionFile: *admission,
		Logf: func(format string, args ...any) { slog.Debug(fmt.Sprintf(format, args...)) }})
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		r.Close()
		return fmt.Errorf("listen %s: %w", *listen, err)
	}
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = r.Shutdown(shutdown)
	}()
	slog.Info("self-hosted DERP relay ready", "address", ln.Addr().String(), "hostname", *hostname, "stun", "disabled", "http_listener", "none")
	return r.Serve(ln)
}
