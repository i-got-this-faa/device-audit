package lab

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"expvar"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/tailscale/tailcat"
	"tailscale.com/derp/derpserver"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/metrics"
	"tailscale.com/types/key"
)

const (
	derpLabOptIn       = "DEVICE_AUDIT_DERP_LAB"
	derpPeerOptIn      = "DEVICE_AUDIT_DERP_PEER"
	derpPeerTestLimit  = 130 * time.Second
	derpLabTestLimit   = 140 * time.Second
	derpDownDuration   = 2 * time.Second
	derpProbeTimeout   = 800 * time.Millisecond
	derpRetryInterval  = 100 * time.Millisecond
	derpRecoveryWindow = 30 * time.Second
)

// derpProtocolCounters contains upstream DERP frame counters, not TLS socket bytes.
type derpProtocolCounters struct {
	PacketsReceived      int64 `json:"packets_received"`
	PacketsSent          int64 `json:"packets_sent"`
	PacketsReceivedDisco int64 `json:"packets_received_disco"`
	PacketsReceivedOther int64 `json:"packets_received_other"`
	PacketsForwardedIn   int64 `json:"packets_forwarded_in"`
	PacketsForwardedOut  int64 `json:"packets_forwarded_out"`
	BytesReceived        int64 `json:"bytes_received"`
	BytesSent            int64 `json:"bytes_sent"`
}

// Attempt timing is relative to the client peer process start.
type applicationAttempt struct {
	Sequence         uint64  `json:"sequence"`
	StartedMS        float64 `json:"started_ms"`
	FinishedMS       float64 `json:"finished_ms"`
	Outcome          string  `json:"outcome"`
	WriteAccepted    bool    `json:"write_accepted"`
	DeliveryUnixNano int64   `json:"delivery_unix_nano,omitempty"`
}

type relayDialAttempt struct {
	StartedMS  float64 `json:"started_ms"`
	FinishedMS float64 `json:"finished_ms"`
	Outcome    string  `json:"outcome"`
}

type relayObservation struct {
	Event                    string                `json:"event"`
	PublicSHA256             string                `json:"public_sha256,omitempty"`
	ServerPublicSHA256       string                `json:"server_public_sha256,omitempty"`
	DERPRegionID             int                   `json:"derp_region_id,omitempty"`
	DERPPort                 int                   `json:"derp_port,omitempty"`
	RelayPath                bool                  `json:"relay_path,omitempty"`
	Direct                   bool                  `json:"direct"`
	PeerBound                bool                  `json:"peer_bound,omitempty"`
	Accepted                 int64                 `json:"accepted,omitempty"`
	ChallengeReplies         int64                 `json:"challenge_replies,omitempty"`
	Delivered                bool                  `json:"delivered"`
	RoundTrips               int                   `json:"round_trips,omitempty"`
	FirstDeliveryUnixNano    int64                 `json:"first_delivery_unix_nano,omitempty"`
	LastDeliveryUnixNano     int64                 `json:"last_delivery_unix_nano,omitempty"`
	DeliveryGapMS            float64               `json:"delivery_gap_ms,omitempty"`
	RelayDownMS              float64               `json:"relay_down_ms,omitempty"`
	RelayReconnectGapMS      float64               `json:"relay_reconnect_gap_ms,omitempty"`
	ReconnectWaitMS          float64               `json:"reconnect_wait_ms,omitempty"`
	RelayReconnectedUnixNano int64                 `json:"relay_reconnected_unix_nano,omitempty"`
	SamePortRestart          bool                  `json:"same_port_restart,omitempty"`
	FirewallDroppedPackets   uint64                `json:"firewall_dropped_packets,omitempty"`
	DERPProtocol             *derpProtocolCounters `json:"derp_protocol,omitempty"`
	ChallengeSequences       []uint64              `json:"challenge_sequences,omitempty"`
	Attempts                 []applicationAttempt  `json:"application_attempts,omitempty"`
	DialAttempts             []relayDialAttempt    `json:"dial_attempts,omitempty"`
	ClockOrigin              string                `json:"clock_origin,omitempty"`
	ClientPID                int                   `json:"client_pid,omitempty"`
	ServerPID                int                   `json:"server_pid,omitempty"`
	ClientExitStatus         *int                  `json:"client_exit_status,omitempty"`
	ServerExitStatus         *int                  `json:"server_exit_status,omitempty"`
	PeersAliveAfterRestart   bool                  `json:"peers_alive_after_restart,omitempty"`
	DERPTotals               *derpProtocolCounters `json:"derp_totals,omitempty"`
}

func TestDERPRelayLab(t *testing.T) {
	if os.Getenv(derpLabOptIn) != "1" {
		t.Skip("isolated DERP relay experiment requires explicit opt-in")
	}
	ctx, cancel := context.WithTimeout(context.Background(), derpLabTestLimit)
	defer cancel()

	selfNetNS, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		t.Fatal("cannot verify isolated network namespace")
	}
	parentNetNS := os.Getenv("DEVICE_AUDIT_DERP_PARENT_NETNS")
	if parentNetNS == "" || selfNetNS == parentNetNS {
		t.Fatal("DERP relay experiment requires an isolated network namespace")
	}
	_ = readUDPDropCount(t, ctx)

	dir := t.TempDir()
	serverPath := filepath.Join(dir, "server.json")
	clientPath := filepath.Join(dir, "client.json")
	if err := InitializeServer(serverPath); err != nil {
		t.Fatal("cannot initialize private server state")
	}
	if err := InitializeClient(clientPath); err != nil {
		t.Fatal("cannot initialize private client state")
	}
	serverState, err := loadServer(serverPath)
	if err != nil {
		t.Fatal("cannot load private server state")
	}
	clientState, err := loadClient(clientPath)
	if err != nil {
		t.Fatal("cannot load private client state")
	}

	derpKey := key.NewNode()
	listenAddress := "127.0.0.1:0"
	region, relay, stopRelay := startRelayWithKey(t, listenAddress, derpKey)
	derpPort := region.Nodes[0].DERPPort
	listenAddress = fmt.Sprintf("127.0.0.1:%d", derpPort)
	server := startDERPRelayPeer(t, ctx, peerConfig{
		Role: "relay_server", State: serverPath, Allowed: clientState.Node.Public(), Region: region,
	})
	var bootstrap struct{ Address tailcat.Addr }
	server.read(t, &bootstrap)
	var serverReady relayObservation
	server.read(t, &serverReady)
	if serverReady.Event != "relay_server_ready" || serverReady.PublicSHA256 != PublicDigest(serverState.Node.Public()) {
		t.Fatal("relay server identity did not match persisted state")
	}

	client := startDERPRelayPeer(t, ctx, peerConfig{
		Role: "relay_client", State: clientPath, Addr: bootstrap.Address, Expected: serverState.Node.Public(),
	})
	var clientReady relayObservation
	client.read(t, &clientReady)
	if clientReady.Event != "relay_client_ready" || clientReady.PublicSHA256 != PublicDigest(clientState.Node.Public()) || clientReady.DERPRegionID != 1 || !clientReady.RelayPath || clientReady.Direct {
		t.Fatal("client did not establish the pinned DERP path")
	}
	initialDrops := readUDPDropCount(t, ctx)
	if initialDrops == 0 {
		t.Fatal("nft UDP-drop counter did not increase during relay discovery")
	}
	clientPID, serverPID := client.cmd.Process.Pid, server.cmd.Process.Pid
	if clientPID == serverPID {
		t.Fatal("relay peers do not have separate operating-system processes")
	}

	beforeBaseline := readDERPProtocolCounters(t, relay)
	client.command(t, "baseline")
	var baseline relayObservation
	client.read(t, &baseline)
	if baseline.Event != "baseline_delivery" || !baseline.Delivered || baseline.RoundTrips != 3 || len(baseline.Attempts) != 3 || len(baseline.DialAttempts) != 1 || baseline.DialAttempts[0].Outcome != "connected" || baseline.DialAttempts[0].FinishedMS < baseline.DialAttempts[0].StartedMS || baseline.FirstDeliveryUnixNano == 0 || baseline.LastDeliveryUnixNano < baseline.FirstDeliveryUnixNano {
		t.Fatal("authenticated baseline challenge exchange failed")
	}
	for i, attempt := range baseline.Attempts {
		if attempt.Sequence != uint64(i+1) || !attempt.WriteAccepted || attempt.Outcome != "delivered" || attempt.DeliveryUnixNano == 0 || attempt.StartedMS < 0 || attempt.FinishedMS < attempt.StartedMS {
			t.Fatal("baseline challenge attempt evidence is incomplete")
		}
	}
	baselineServer := relayServerSnapshot(t, server, int64(baseline.RoundTrips))
	if !baselineServer.PeerBound || !baselineServer.RelayPath || baselineServer.Direct || baselineServer.Accepted == 0 || baselineServer.ChallengeReplies < int64(baseline.RoundTrips) || len(baselineServer.ChallengeSequences) != baseline.RoundTrips {
		t.Fatal("baseline application traffic was not bound to the admitted relay peer")
	}
	for _, attempt := range baseline.Attempts {
		if !containsSequence(baselineServer.ChallengeSequences, attempt.Sequence) {
			t.Fatal("server did not receive a baseline challenge sequence")
		}
	}
	afterBaseline := readDERPProtocolCounters(t, relay)
	baselineProtocol := afterBaseline.subtract(beforeBaseline)
	assertDERPDataActivity(t, baselineProtocol)
	if afterBaseline.PacketsReceivedDisco == 0 {
		t.Fatal("DERP server did not count received Disco protocol packets")
	}
	logRelayObservation(t, relayObservation{
		Event: "baseline_delivery", DERPRegionID: clientReady.DERPRegionID, DERPPort: derpPort, RelayPath: true,
		Delivered: true, RoundTrips: baseline.RoundTrips, Attempts: baseline.Attempts,
		PublicSHA256: clientReady.PublicSHA256, ServerPublicSHA256: serverReady.PublicSHA256,
		ClockOrigin: baseline.ClockOrigin, ClientPID: clientPID, ServerPID: serverPID,
		FirstDeliveryUnixNano: baseline.FirstDeliveryUnixNano, LastDeliveryUnixNano: baseline.LastDeliveryUnixNano,
		PeerBound: baselineServer.PeerBound, ChallengeReplies: baselineServer.ChallengeReplies,
		ChallengeSequences: baselineServer.ChallengeSequences, DERPProtocol: &baselineProtocol, DERPTotals: &afterBaseline,
	})

	stopRelay()
	relayDownAt := time.Now()
	if conn, err := net.DialTimeout("tcp", listenAddress, 150*time.Millisecond); err == nil {
		conn.Close()
		t.Fatal("DERP listener remained reachable after shutdown")
	}
	client.command(t, "outage_probe")
	var outage relayObservation
	client.read(t, &outage)
	if outage.Event != "outage_probe" || outage.Delivered || outage.RoundTrips != 0 || len(outage.Attempts) != 1 || !outage.Attempts[0].WriteAccepted || (outage.Attempts[0].Outcome != "timeout_no_reply" && outage.Attempts[0].Outcome != "read_error") || outage.Attempts[0].Sequence != baseline.Attempts[len(baseline.Attempts)-1].Sequence+1 || outage.ClockOrigin != baseline.ClockOrigin || outage.Attempts[0].StartedMS <= baseline.Attempts[len(baseline.Attempts)-1].FinishedMS || outage.Attempts[0].FinishedMS < outage.Attempts[0].StartedMS {
		t.Fatal("application challenge received no reply over the existing peer connection during the outage")
	}
	server.command(t, "snapshot")
	var outageServer relayObservation
	server.read(t, &outageServer)
	if outageServer.ChallengeReplies != baselineServer.ChallengeReplies || len(outageServer.ChallengeSequences) != len(baselineServer.ChallengeSequences) || containsSequence(outageServer.ChallengeSequences, outage.Attempts[0].Sequence) {
		t.Fatal("server received an application challenge during the relay outage")
	}
	if wait := time.Until(relayDownAt.Add(derpDownDuration)); wait > 0 {
		timer := time.NewTimer(wait)
		select {
		case <-timer.C:
		case <-ctx.Done():
			t.Fatal("DERP outage exceeded the experiment deadline")
		}
	}

	restartedRegion, restartedRelay, _ := startRelayWithKey(t, listenAddress, derpKey)
	restartReadyAt := time.Now()
	samePort := restartedRegion.Nodes[0].DERPPort == derpPort
	if !samePort || restartedRegion.RegionID != region.RegionID {
		t.Fatal("DERP restart did not retain the same port and region")
	}
	relayDownMS := float64(restartReadyAt.Sub(relayDownAt).Microseconds()) / 1000
	outage.DERPRegionID = clientReady.DERPRegionID
	outage.DERPPort = derpPort
	outage.RelayDownMS = relayDownMS
	outage.ChallengeReplies = outageServer.ChallengeReplies
	outage.PublicSHA256 = clientReady.PublicSHA256
	outage.ServerPublicSHA256 = serverReady.PublicSHA256
	outage.ChallengeSequences = outageServer.ChallengeSequences
	if !relayPeerAlive(client) || !relayPeerAlive(server) || client.cmd.Process.Pid != clientPID || server.cmd.Process.Pid != serverPID {
		t.Fatal("a peer process exited or changed while DERP was restarted")
	}
	outage.ClientPID = clientPID
	outage.ServerPID = serverPID
	outage.PeersAliveAfterRestart = true
	outage.SamePortRestart = samePort
	logRelayObservation(t, outage)

	restartedBefore := readDERPProtocolCounters(t, restartedRelay)
	client.command(t, "relay_ping")
	var restored relayObservation
	client.read(t, &restored)
	if restored.Event != "relay_reconnected" || restored.DERPRegionID != 1 || !restored.RelayPath || restored.Direct || restored.RelayReconnectedUnixNano <= restartReadyAt.UnixNano() {
		t.Fatal("existing client process did not reconnect through the restarted DERP")
	}
	relayReconnectGapMS := float64(restored.RelayReconnectedUnixNano-restartReadyAt.UnixNano()) / float64(time.Millisecond)
	client.command(t, "recovery")
	var recovery relayObservation
	client.read(t, &recovery)
	if recovery.Event != "recovery_delivery" || !recovery.Delivered || recovery.RoundTrips != 1 || recovery.FirstDeliveryUnixNano <= baseline.LastDeliveryUnixNano {
		t.Fatal("authenticated application delivery did not recover")
	}
	recoveryServer := relayServerSnapshot(t, server, outageServer.ChallengeReplies+1)
	if !recoveryServer.PeerBound || !recoveryServer.RelayPath || recoveryServer.Direct || recoveryServer.Accepted == 0 || recoveryServer.ChallengeReplies <= outageServer.ChallengeReplies {
		t.Fatal("recovered application traffic was not bound to the admitted relay peer")
	}
	if !relayPeerAlive(client) || !relayPeerAlive(server) || client.cmd.Process.Pid != clientPID || server.cmd.Process.Pid != serverPID {
		t.Fatal("a peer process exited or changed before recovery evidence was collected")
	}
	restartedAfter := readDERPProtocolCounters(t, restartedRelay)
	restartedProtocol := restartedAfter.subtract(restartedBefore)
	assertDERPDataActivity(t, restartedProtocol)
	if restartedAfter.PacketsReceivedDisco == 0 {
		t.Fatal("restarted DERP server did not count received Disco protocol packets")
	}
	if recoveryServer.ChallengeReplies <= baselineServer.ChallengeReplies {
		t.Fatal("restarted server did not validate a fresh application challenge")
	}
	var recoverySequence uint64
	seenSequences := make(map[uint64]bool, len(recovery.Attempts))
	for i := range recovery.Attempts {
		attempt := &recovery.Attempts[i]
		if attempt.Sequence <= uint64(baseline.RoundTrips) || seenSequences[attempt.Sequence] || attempt.Outcome == "" || attempt.StartedMS < 0 || attempt.FinishedMS < attempt.StartedMS {
			t.Fatal("recovery attempt sequence or timing evidence is invalid")
		}
		seenSequences[attempt.Sequence] = true
		if containsSequence(recoveryServer.ChallengeSequences, attempt.Sequence) && attempt.Outcome != "delivered" && attempt.Outcome != "delivered_after_restart" {
			attempt.Outcome = "server_received_no_client_reply_observed"
		}
		if attempt.Outcome == "delivered" || attempt.Outcome == "delivered_after_restart" {
			recoverySequence = attempt.Sequence
			if !attempt.WriteAccepted || attempt.DeliveryUnixNano == 0 || attempt.DeliveryUnixNano != recovery.FirstDeliveryUnixNano || !containsSequence(recoveryServer.ChallengeSequences, attempt.Sequence) {
				t.Fatal("recovered challenge sequence was not validated end-to-end")
			}
		}
	}

	for _, attempt := range recovery.DialAttempts {
		if attempt.Outcome == "" || attempt.StartedMS < 0 || attempt.FinishedMS < attempt.StartedMS {
			t.Fatal("recovery dial attempt evidence is incomplete")
		}
	}
	if recoverySequence == 0 {
		t.Fatal("recovery report has no validated challenge sequence")
	}

	deliveryGapMS := float64(recovery.FirstDeliveryUnixNano-baseline.LastDeliveryUnixNano) / float64(time.Millisecond)
	if deliveryGapMS < 1500 {
		t.Fatal("measured application delivery gap did not include the relay outage")
	}
	finalDrops := readUDPDropCount(t, ctx)
	logRelayObservation(t, relayObservation{
		Event: "recovery_delivery", DERPRegionID: restored.DERPRegionID, DERPPort: derpPort,
		RelayPath: true, Direct: recoveryServer.Direct, PeerBound: recoveryServer.PeerBound,
		Delivered: true, RoundTrips: recovery.RoundTrips, SamePortRestart: samePort,
		Attempts: recovery.Attempts, DialAttempts: recovery.DialAttempts, ClockOrigin: recovery.ClockOrigin,
		PublicSHA256: clientReady.PublicSHA256, ServerPublicSHA256: serverReady.PublicSHA256,
		ClientPID: clientPID, ServerPID: serverPID, PeersAliveAfterRestart: true,
		FirstDeliveryUnixNano: recovery.FirstDeliveryUnixNano, LastDeliveryUnixNano: recovery.LastDeliveryUnixNano,
		DeliveryGapMS: deliveryGapMS, RelayDownMS: relayDownMS, RelayReconnectGapMS: relayReconnectGapMS,
		ReconnectWaitMS: restored.ReconnectWaitMS, RelayReconnectedUnixNano: restored.RelayReconnectedUnixNano,
		ChallengeReplies: recoveryServer.ChallengeReplies, FirewallDroppedPackets: finalDrops,
		Accepted: recoveryServer.Accepted, ChallengeSequences: recoveryServer.ChallengeSequences,
		DERPProtocol: &restartedProtocol, DERPTotals: &restartedAfter,
	})

	client.command(t, "stop")
	client.wait(t)
	server.command(t, "stop")
	server.wait(t)
	if client.cmd.ProcessState == nil || server.cmd.ProcessState == nil || client.cmd.ProcessState.ExitCode() != 0 || server.cmd.ProcessState.ExitCode() != 0 {
		t.Fatal("relay peer subprocesses did not exit successfully")
	}
	clientExit, serverExit := client.cmd.ProcessState.ExitCode(), server.cmd.ProcessState.ExitCode()
	logRelayObservation(t, relayObservation{
		Event: "peer_process_exit", ClientPID: clientPID, ServerPID: serverPID,
		ClientExitStatus: &clientExit, ServerExitStatus: &serverExit,
	})
}

func TestDERPRelayPeer(t *testing.T) {
	if os.Getenv(derpPeerOptIn) != "1" {
		t.Skip("relay subprocess entry point")
	}
	log.SetOutput(io.Discard)
	var cfg peerConfig
	in := json.NewDecoder(os.Stdin)
	if err := in.Decode(&cfg); err != nil {
		t.Fatal("invalid private relay peer configuration")
	}
	ctx, cancel := context.WithTimeout(context.Background(), derpPeerTestLimit-5*time.Second)
	defer cancel()
	switch cfg.Role {
	case "relay_server":
		runDERPRelayServer(t, ctx, cfg, in, json.NewEncoder(os.Stdout))
	case "relay_client":
		runDERPRelayClient(t, ctx, cfg, in, json.NewEncoder(os.Stdout))
	default:
		t.Fatal("invalid relay peer role")
	}
}

func relayPeerAlive(peer *child) bool {
	if peer == nil || peer.cmd == nil || peer.cmd.Process == nil || peer.cmd.ProcessState != nil {
		return false
	}
	return peer.cmd.Process.Signal(syscall.Signal(0)) == nil
}

func runDERPRelayServer(t *testing.T, ctx context.Context, cfg peerConfig, in *json.Decoder, out *json.Encoder) {
	s, err := StartServer(ctx, cfg.State, cfg.Allowed, cfg.Region)
	if err != nil {
		t.Fatal("relay server startup failed")
	}
	ln, err := s.Listen(ctx, "tcp", fmt.Sprintf(":%d", labPort))
	if err != nil {
		s.Close()
		t.Fatal("relay application listener failed")
	}
	var accepted atomic.Int64
	var replies atomic.Int64
	var bound atomic.Bool
	var sequenceMu sync.Mutex
	var sequences []uint64
	var activeMu sync.Mutex
	active := make(map[net.Conn]struct{})
	var workers sync.WaitGroup
	acceptDone := make(chan struct{})
	go func() {
		defer close(acceptDone)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			activeMu.Lock()
			active[conn] = struct{}{}
			workers.Add(1)
			activeMu.Unlock()
			go func(conn net.Conn) {
				defer workers.Done()
				defer conn.Close()
				defer func() {
					activeMu.Lock()
					delete(active, conn)
					activeMu.Unlock()
				}()
				peer, ok := s.PeerKey(conn.RemoteAddr())
				if !ok || peer != cfg.Allowed {
					return
				}
				bound.Store(true)
				for {
					var challenge [32]byte
					if _, err := io.ReadFull(conn, challenge[:]); err != nil {
						return
					}
					sequence := binary.BigEndian.Uint64(challenge[:8])
					sequenceMu.Lock()
					sequences = append(sequences, sequence)
					sequenceMu.Unlock()
					reply := sha256.Sum256(challenge[:])
					if _, err := conn.Write(reply[:]); err != nil {
						return
					}
					replies.Add(1)
				}
			}(conn)
		}
	}()
	defer func() {
		_ = ln.Close()
		<-acceptDone
		activeMu.Lock()
		connections := make([]net.Conn, 0, len(active))
		for conn := range active {
			connections = append(connections, conn)
		}
		activeMu.Unlock()
		for _, conn := range connections {
			_ = conn.Close()
		}
		workers.Wait()
		_ = s.Close()
	}()

	state, err := loadServer(cfg.State)
	if err != nil {
		t.Fatal("relay server identity unavailable")
	}
	if err := out.Encode(struct{ Address tailcat.Addr }{s.TailcatAddr()}); err != nil {
		t.Fatal("private relay bootstrap pipe failed")
	}
	if err := out.Encode(relayObservation{Event: "relay_server_ready", PublicSHA256: PublicDigest(state.Node.Public())}); err != nil {
		t.Fatal("relay server report pipe failed")
	}
	for {
		var command string
		if err := in.Decode(&command); err != nil {
			return
		}
		switch command {
		case "snapshot":
			sequenceMu.Lock()
			challengeSequences := append([]uint64(nil), sequences...)
			sequenceMu.Unlock()
			observation := relayObservation{
				Event: "server_snapshot", PeerBound: bound.Load(), Accepted: accepted.Load(),
				ChallengeReplies: replies.Load(), ChallengeSequences: challengeSequences,
			}
			for _, peer := range s.Status().Peer {
				if peer.PublicKey == cfg.Allowed {
					observation.Direct = peer.CurAddr != ""
					observation.RelayPath = peer.CurAddr == "" && peer.Relay != ""
					break
				}
			}
			if err := out.Encode(observation); err != nil {
				t.Fatal("relay server report pipe failed")
			}
		case "stop":
			return
		default:
			t.Fatal("invalid relay server command")
		}
	}
}

func runDERPRelayClient(t *testing.T, ctx context.Context, cfg peerConfig, in *json.Decoder, out *json.Encoder) {
	peerStarted := time.Now()
	c, err := NewClient(cfg.State, cfg.Addr, cfg.Expected)
	if err != nil {
		t.Fatal("relay client startup failed")
	}
	defer c.Close()
	var appConn net.Conn
	defer func() {
		if appConn != nil {
			_ = appConn.Close()
		}
	}()
	var nextSequence uint64
	var outageChallenge *pendingChallenge

	result, err := waitForDERP(ctx, c, derpRecoveryWindow)
	if err != nil {
		t.Fatal("initial DERP path discovery failed")
	}
	state, err := loadClient(cfg.State)
	if err != nil {
		t.Fatal("relay client identity unavailable")
	}
	if err := out.Encode(relayObservation{
		Event: "relay_client_ready", PublicSHA256: PublicDigest(state.Node.Public()),
		DERPRegionID: int(result.DERPRegionID), RelayPath: true,
	}); err != nil {
		t.Fatal("relay client report pipe failed")
	}

	for {
		var command string
		if err := in.Decode(&command); err != nil {
			return
		}
		switch command {
		case "baseline":
			if appConn != nil {
				t.Fatal("baseline application connection already exists")
			}
			var dial relayDialAttempt
			appConn, dial, err = dialRelayApplication(ctx, c, 8*time.Second, peerStarted)
			if err != nil {
				t.Fatal("baseline application dial failed")
			}
			attemptCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
			attempts := make([]applicationAttempt, 0, 3)
			for range 3 {
				nextSequence++
				pending, challengeErr := relayChallenge(attemptCtx, appConn, nextSequence, peerStarted)
				if challengeErr != nil {
					cancel()
					t.Fatal("authenticated baseline challenge exchange failed")
				}
				attempts = append(attempts, pending.Attempt)
			}
			cancel()
			if err := out.Encode(relayObservation{
				Event: "baseline_delivery", Delivered: true, RoundTrips: len(attempts),
				FirstDeliveryUnixNano: attempts[0].DeliveryUnixNano,
				LastDeliveryUnixNano:  attempts[len(attempts)-1].DeliveryUnixNano,
				Attempts:              attempts, DialAttempts: []relayDialAttempt{dial}, ClockOrigin: "client_process_start",
			}); err != nil {
				t.Fatal("relay client report pipe failed")
			}
		case "outage_probe":
			if appConn == nil {
				t.Fatal("outage probe requires the established application connection")
			}
			nextSequence++
			probeCtx, cancel := context.WithTimeout(ctx, derpProbeTimeout)
			pending, challengeErr := relayChallenge(probeCtx, appConn, nextSequence, peerStarted)
			cancel()
			if errors.Is(challengeErr, errChallengeMismatch) || errors.Is(challengeErr, errChallengeRandom) {
				t.Fatal("outage challenge validation failed")
			}
			if pending.Attempt.WriteAccepted && challengeErr != nil {
				outageChallenge = &pending
			}
			attempt := pending.Attempt
			if err := out.Encode(relayObservation{
				Event: "outage_probe", Delivered: challengeErr == nil, RoundTrips: boolCount(challengeErr == nil),
				FirstDeliveryUnixNano: attempt.DeliveryUnixNano, LastDeliveryUnixNano: attempt.DeliveryUnixNano,
				Attempts: []applicationAttempt{attempt}, ClockOrigin: "client_process_start",
			}); err != nil {
				t.Fatal("relay client report pipe failed")
			}
		case "relay_ping":
			reconnectStarted := time.Now()
			result, err := waitForDERP(ctx, c, derpRecoveryWindow)
			reconnectedAt := time.Now()
			if err != nil {
				t.Fatal("DERP reconnect was not observed")
			}
			if err := out.Encode(relayObservation{
				Event: "relay_reconnected", DERPRegionID: int(result.DERPRegionID), RelayPath: true,
				ClockOrigin:              "client_process_start",
				ReconnectWaitMS:          float64(reconnectedAt.Sub(reconnectStarted).Microseconds()) / 1000,
				RelayReconnectedUnixNano: reconnectedAt.UnixNano(),
			}); err != nil {
				t.Fatal("relay client report pipe failed")
			}
		case "recovery":
			recoveryCtx, cancel := context.WithTimeout(ctx, derpRecoveryWindow)
			attempts := make([]applicationAttempt, 0, 4)
			var deliveredAt int64
			if outageChallenge != nil && appConn != nil {
				pendingCtx, stop := context.WithTimeout(recoveryCtx, 2*time.Second)
				pending, pendingErr := readRelayChallenge(pendingCtx, appConn, *outageChallenge, peerStarted, "delivered_after_restart")
				stop()
				attempts = append(attempts, pending.Attempt)
				if errors.Is(pendingErr, errChallengeMismatch) {
					cancel()
					t.Fatal("pending outage challenge response did not match")
				}
				if pendingErr == nil {
					deliveredAt = pending.Attempt.DeliveryUnixNano
				}
			}
			if deliveredAt == 0 && appConn != nil {
				_ = appConn.Close()
				appConn = nil
			}
			dialAttempts := make([]relayDialAttempt, 0, 6)
			for range 6 {
				if deliveredAt != 0 || recoveryCtx.Err() != nil {
					break
				}
				conn, dial, dialErr := dialRelayApplication(recoveryCtx, c, 2*time.Second, peerStarted)
				dialAttempts = append(dialAttempts, dial)
				if dialErr != nil {
					time.Sleep(derpRetryInterval)
					continue
				}
				nextSequence++
				attemptCtx, stop := context.WithTimeout(recoveryCtx, 2*time.Second)
				pending, challengeErr := relayChallenge(attemptCtx, conn, nextSequence, peerStarted)
				stop()
				attempts = append(attempts, pending.Attempt)
				if challengeErr == nil {
					appConn = conn
					deliveredAt = pending.Attempt.DeliveryUnixNano
					break
				}
				_ = conn.Close()
				if errors.Is(challengeErr, errChallengeMismatch) || errors.Is(challengeErr, errChallengeRandom) {
					cancel()
					t.Fatal("recovered challenge validation failed")
				}
				time.Sleep(derpRetryInterval)
			}
			cancel()
			if err := out.Encode(relayObservation{
				Event: "recovery_delivery", Delivered: deliveredAt != 0, RoundTrips: boolCount(deliveredAt != 0),
				FirstDeliveryUnixNano: deliveredAt, LastDeliveryUnixNano: deliveredAt,
				Attempts: attempts, DialAttempts: dialAttempts, ClockOrigin: "client_process_start",
			}); err != nil {
				t.Fatal("relay client report pipe failed")
			}
		case "stop":
			return
		default:
			t.Fatal("invalid relay client command")
		}
	}
}

var (
	errChallengeMismatch = errors.New("relay challenge response mismatch")
	errChallengeRandom   = errors.New("relay challenge generation failed")
)

// pendingChallenge allows a timed-out outage request to be checked after reconnect.
type pendingChallenge struct {
	Attempt  applicationAttempt
	Expected [32]byte
}

func dialRelayApplication(ctx context.Context, c *tailcat.Client, timeout time.Duration, origin time.Time) (net.Conn, relayDialAttempt, error) {
	started := time.Now()
	attempt := relayDialAttempt{StartedMS: elapsedMilliseconds(origin, started)}
	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	conn, err := c.DialTCPPort(dialCtx, labPort)
	cancel()
	finished := time.Now()
	attempt.FinishedMS = elapsedMilliseconds(origin, finished)
	if err != nil {
		attempt.Outcome = "failed"
		return nil, attempt, err
	}
	attempt.Outcome = "connected"
	return conn, attempt, nil
}

func relayChallenge(ctx context.Context, conn net.Conn, sequence uint64, origin time.Time) (pendingChallenge, error) {
	started := time.Now()
	pending := pendingChallenge{Attempt: applicationAttempt{
		Sequence: sequence, StartedMS: elapsedMilliseconds(origin, started),
	}}
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = started.Add(5 * time.Second)
	}
	if err := conn.SetDeadline(deadline); err != nil {
		pending.Attempt.Outcome = "connection_error"
		pending.Attempt.FinishedMS = elapsedMilliseconds(origin, time.Now())
		return pending, err
	}
	var challenge [32]byte
	binary.BigEndian.PutUint64(challenge[:8], sequence)
	if _, err := rand.Read(challenge[8:]); err != nil {
		pending.Attempt.Outcome = "challenge_generation_failed"
		pending.Attempt.FinishedMS = elapsedMilliseconds(origin, time.Now())
		return pending, errChallengeRandom
	}
	pending.Expected = sha256.Sum256(challenge[:])
	n, err := conn.Write(challenge[:])
	if err != nil || n != len(challenge) {
		pending.Attempt.Outcome = "write_error"
		pending.Attempt.FinishedMS = elapsedMilliseconds(origin, time.Now())
		if err == nil {
			err = io.ErrShortWrite
		}
		return pending, err
	}
	pending.Attempt.WriteAccepted = true
	return readRelayChallenge(ctx, conn, pending, origin, "delivered")
}

func readRelayChallenge(ctx context.Context, conn net.Conn, pending pendingChallenge, origin time.Time, successOutcome string) (pendingChallenge, error) {
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(5 * time.Second)
	}
	if err := conn.SetDeadline(deadline); err != nil {
		pending.Attempt.Outcome = "read_error_unconfirmed"
		pending.Attempt.FinishedMS = elapsedMilliseconds(origin, time.Now())
		return pending, err
	}
	var reply [32]byte
	if _, err := io.ReadFull(conn, reply[:]); err != nil {
		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			if successOutcome == "delivered_after_restart" {
				pending.Attempt.Outcome = "timeout_unconfirmed"
			} else {
				pending.Attempt.Outcome = "timeout_no_reply"
			}
		} else if successOutcome == "delivered_after_restart" {
			pending.Attempt.Outcome = "read_error_unconfirmed"
		} else {
			pending.Attempt.Outcome = "read_error"
		}
		pending.Attempt.FinishedMS = elapsedMilliseconds(origin, time.Now())
		return pending, err
	}
	if reply != pending.Expected {
		pending.Attempt.Outcome = "response_mismatch"
		pending.Attempt.FinishedMS = elapsedMilliseconds(origin, time.Now())
		return pending, errChallengeMismatch
	}
	deliveredAt := time.Now()
	pending.Attempt.Outcome = successOutcome
	pending.Attempt.FinishedMS = elapsedMilliseconds(origin, deliveredAt)
	pending.Attempt.DeliveryUnixNano = deliveredAt.UnixNano()
	return pending, nil
}

func elapsedMilliseconds(origin, at time.Time) float64 {
	return float64(at.Sub(origin).Microseconds()) / 1000
}

func waitForDERP(ctx context.Context, c *tailcat.Client, timeout time.Duration) (*ipnstate.PingResult, error) {
	waitCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	for waitCtx.Err() == nil {
		pingCtx, stop := context.WithTimeout(waitCtx, 2*time.Second)
		result, err := c.DiscoPing(pingCtx)
		stop()
		if err == nil && result != nil {
			if result.Endpoint != "" {
				return nil, errors.New("direct path appeared while UDP firewall is active")
			}
			if result.DERPRegionID == 1 {
				return result, nil
			}
		}
		select {
		case <-waitCtx.Done():
		case <-time.After(derpRetryInterval):
		}
	}
	return nil, errors.New("DERP path unavailable")
}

func boolCount(ok bool) int {
	if ok {
		return 1
	}
	return 0
}

func containsSequence(sequences []uint64, target uint64) bool {
	for _, sequence := range sequences {
		if sequence == target {
			return true
		}
	}
	return false
}

func relayServerSnapshot(t *testing.T, server *child, minimumReplies int64) relayObservation {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		server.command(t, "snapshot")
		var snapshot relayObservation
		server.read(t, &snapshot)
		if snapshot.Event != "server_snapshot" {
			t.Fatal("relay server returned an unexpected snapshot")
		}
		if snapshot.ChallengeReplies >= minimumReplies {
			return snapshot
		}
		if time.Now().After(deadline) {
			t.Fatal("authenticated server did not complete the expected challenge replies")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func startDERPRelayPeer(t *testing.T, ctx context.Context, cfg peerConfig) *child {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal("cannot locate relay peer test binary")
	}
	cmd := exec.CommandContext(ctx, exe, "-test.run=^TestDERPRelayPeer$", fmt.Sprintf("-test.timeout=%s", derpPeerTestLimit.String()))
	cmd.Env = []string{derpPeerOptIn + "=1", "HOME=" + t.TempDir(), "PATH=" + os.Getenv("PATH")}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal("cannot open private relay configuration pipe")
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal("cannot open relay report pipe")
	}
	p := &child{cmd: cmd, in: json.NewEncoder(stdin), out: bufio.NewScanner(stdout)}
	cmd.Stderr = io.Discard
	if err := cmd.Start(); err != nil {
		t.Fatal("cannot start relay peer process")
	}
	t.Cleanup(func() { p.waitOnce.Do(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }) })
	if err := p.in.Encode(cfg); err != nil {
		t.Fatal("private relay peer configuration failed")
	}
	return p
}

func readDERPProtocolCounters(t *testing.T, server *derpserver.Server) derpProtocolCounters {
	t.Helper()
	set, ok := server.ExpVar(false).(*metrics.Set)
	if !ok {
		t.Fatal("pinned DERP protocol metrics have an unexpected type")
	}
	kinds, ok := set.Get("counter_packets_received_kind").(*metrics.LabelMap)
	if !ok {
		t.Fatal("pinned DERP packet-kind metrics are unavailable")
	}
	return derpProtocolCounters{
		PacketsReceived:      relayCounter(t, set, "packets_received"),
		PacketsSent:          relayCounter(t, set, "packets_sent"),
		PacketsReceivedDisco: kinds.Get("disco").Value(),
		PacketsReceivedOther: kinds.Get("other").Value(),
		PacketsForwardedIn:   relayCounter(t, set, "packets_forwarded_in"),
		PacketsForwardedOut:  relayCounter(t, set, "packets_forwarded_out"),
		BytesReceived:        relayCounter(t, set, "bytes_received"),
		BytesSent:            relayCounter(t, set, "bytes_sent"),
	}
}

func relayCounter(t *testing.T, set *metrics.Set, name string) int64 {
	t.Helper()
	value, ok := set.Get(name).(*expvar.Int)
	if !ok {
		t.Fatalf("pinned DERP protocol counter %s is unavailable", name)
	}
	return value.Value()
}

func (after derpProtocolCounters) subtract(before derpProtocolCounters) derpProtocolCounters {
	return derpProtocolCounters{
		PacketsReceived:      after.PacketsReceived - before.PacketsReceived,
		PacketsSent:          after.PacketsSent - before.PacketsSent,
		PacketsReceivedDisco: after.PacketsReceivedDisco - before.PacketsReceivedDisco,
		PacketsReceivedOther: after.PacketsReceivedOther - before.PacketsReceivedOther,
		PacketsForwardedIn:   after.PacketsForwardedIn - before.PacketsForwardedIn,
		PacketsForwardedOut:  after.PacketsForwardedOut - before.PacketsForwardedOut,
		BytesReceived:        after.BytesReceived - before.BytesReceived,
		BytesSent:            after.BytesSent - before.BytesSent,
	}
}

func assertDERPDataActivity(t *testing.T, counters derpProtocolCounters) {
	t.Helper()
	// Forwarded counters describe DERP-to-DERP meshing, absent in this one-relay lab.
	if counters.PacketsReceived <= 0 || counters.PacketsSent <= 0 || counters.PacketsReceivedOther <= 0 || counters.BytesReceived <= 0 || counters.BytesSent <= 0 {
		t.Fatal("DERP protocol packet RX/TX counters did not record relayed application traffic")
	}
}

func readUDPDropCount(t *testing.T, ctx context.Context) uint64 {
	t.Helper()
	commandCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	output, err := exec.CommandContext(commandCtx, "nft", "-j", "list", "table", "inet", "device_audit_derp").Output()
	if err != nil {
		t.Fatal("cannot inspect isolated DERP UDP-drop firewall")
	}
	var document struct {
		Nftables []map[string]json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal(output, &document); err != nil {
		t.Fatal("isolated DERP firewall returned invalid JSON")
	}

	tableCount, chainCount, ruleCount := 0, 0, 0
	var dropped uint64
	for _, entry := range document.Nftables {
		if raw, ok := entry["table"]; ok {
			var table struct {
				Family string `json:"family"`
				Name   string `json:"name"`
			}
			if json.Unmarshal(raw, &table) == nil && table.Family == "inet" && table.Name == "device_audit_derp" {
				tableCount++
			}
		}
		if raw, ok := entry["chain"]; ok {
			var chain struct {
				Family   string          `json:"family"`
				Table    string          `json:"table"`
				Name     string          `json:"name"`
				Type     string          `json:"type"`
				Hook     string          `json:"hook"`
				Priority json.RawMessage `json:"prio"`
				Policy   string          `json:"policy"`
			}
			if json.Unmarshal(raw, &chain) == nil && chain.Family == "inet" && chain.Table == "device_audit_derp" && chain.Name == "output" && chain.Type == "filter" && chain.Hook == "output" && bytes.Equal(bytes.TrimSpace(chain.Priority), []byte("0")) && chain.Policy == "accept" {
				chainCount++
			}
		}
		if raw, ok := entry["rule"]; ok {
			var rule struct {
				Family string            `json:"family"`
				Table  string            `json:"table"`
				Chain  string            `json:"chain"`
				Expr   []json.RawMessage `json:"expr"`
			}
			if json.Unmarshal(raw, &rule) != nil || rule.Family != "inet" || rule.Table != "device_audit_derp" || rule.Chain != "output" {
				continue
			}
			ruleCount++
			hasUDPMatch, hasCounter, hasDrop := false, false, false
			for _, exprRaw := range rule.Expr {
				var expr map[string]json.RawMessage
				if json.Unmarshal(exprRaw, &expr) != nil {
					continue
				}
				if rawMatch, ok := expr["match"]; ok {
					var match struct {
						Op   string `json:"op"`
						Left struct {
							Meta struct {
								Key string `json:"key"`
							} `json:"meta"`
						} `json:"left"`
						Right json.RawMessage `json:"right"`
					}
					var protocol string
					if json.Unmarshal(rawMatch, &match) == nil && json.Unmarshal(match.Right, &protocol) == nil && match.Op == "==" && match.Left.Meta.Key == "l4proto" && protocol == "udp" {
						hasUDPMatch = true
					}
				}
				if rawCounter, ok := expr["counter"]; ok {
					var counter struct {
						Packets uint64 `json:"packets"`
					}
					if json.Unmarshal(rawCounter, &counter) == nil {
						dropped = counter.Packets
						hasCounter = true
					}
				}
				if _, ok := expr["drop"]; ok {
					hasDrop = true
				}
			}
			if !hasUDPMatch || !hasCounter || !hasDrop {
				t.Fatal("isolated DERP firewall is not the expected counted UDP-drop rule")
			}
		}
	}
	if tableCount != 1 || chainCount != 1 || ruleCount != 1 {
		t.Fatal("isolated DERP firewall table, chain, or rule is missing")
	}
	return dropped
}

func logRelayObservation(t *testing.T, observation relayObservation) {
	t.Helper()
	encoded, err := json.Marshal(observation)
	if err != nil {
		t.Fatal("cannot encode safe relay evidence")
	}
	t.Log(string(encoded))
}
