package controller

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/i-got-this-faa/device-audit/infra/database"
	"github.com/i-got-this-faa/device-audit/packages/contracts"
)

const (
	repositoryWriterURLEnv                = "DEVICE_AUDIT_TEST_WRITER_URL"
	repositoryWriterOperationEnv          = "DEVICE_AUDIT_TEST_WRITER_OPERATION"
	repositoryRestartTestEnv              = "TEST_POSTGRES_RESTART"
	repositoryWriterEnroll                = "enroll"
	repositoryWriterEvidence              = "evidence"
	repositoryWriterCommitted             = "committed"
	repositoryWriterApplicationName       = "device-audit-83-writer"
	repositoryWriterLockKey         int64 = 830083
)

// The subprocess calls the real repository and stops before delivering any
// application response. Parent tests kill it at database-observed boundaries.
func TestRepositoryWriterProcess(t *testing.T) {
	databaseURL := os.Getenv(repositoryWriterURLEnv)
	if databaseURL == "" {
		return
	}
	db, err := database.Open(context.Background(), databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repo := fixtureRepository(t, db)
	enrollment, evidence := repositoryEnvelopes(t)
	if os.Getenv(repositoryWriterOperationEnv) == repositoryWriterEnroll {
		if err := db.QueryRow(`SELECT id FROM enrollment_challenges WHERE consumed_at IS NULL`).Scan(&enrollment.ChallengeID); err != nil {
			t.Fatal(err)
		}
		signRepositoryEnrollment(t, &enrollment)
		err = repo.Enroll(context.Background(), enrollment)
	} else {
		err = repo.AcceptEvidence(context.Background(), evidence)
	}
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprintln(os.Stdout, repositoryWriterCommitted)
	var responseGate [1]byte
	_, _ = io.ReadFull(os.Stdin, responseGate[:])
}

func waitRepositoryCondition(t *testing.T, condition func(context.Context) (bool, error)) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), repositoryTestTimeout)
	defer cancel()
	ticker := time.NewTicker(repositoryTestPollInterval)
	defer ticker.Stop()
	for {
		ready, err := condition(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if ready {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatal("timed out waiting for database-observed writer state")
		case <-ticker.C:
		}
	}
}

func TestRepositoryWriterKillBeforeAndAfterCommit(t *testing.T) {
	for _, operation := range []string{repositoryWriterEnroll, repositoryWriterEvidence} {
		for _, committed := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/committed=%v", operation, committed), func(t *testing.T) {
				db, databaseURL := openRepositoryTestDB(t)
				repo := fixtureRepository(t, db)
				enrollment, _ := repositoryEnvelopes(t)
				if operation == repositoryWriterEvidence {
					enrollRepositoryFixture(t, repo)
				} else {
					if _, err := repo.CreateEnrollmentChallenge(context.Background(), enrollment.DeviceID, repositoryFixtureKey().Public().(ed25519.PublicKey), repositoryFixtureAuthorizationReference); err != nil {
						t.Fatal(err)
					}
				}
				var blocker *sql.Conn
				if !committed {
					var err error
					blocker, err = db.Conn(context.Background())
					if err != nil {
						t.Fatal(err)
					}
					defer blocker.Close()
					if _, err := blocker.ExecContext(context.Background(), `SELECT pg_advisory_lock($1)`, repositoryWriterLockKey); err != nil {
						t.Fatal(err)
					}
					defer blocker.ExecContext(context.Background(), `SELECT pg_advisory_unlock($1)`, repositoryWriterLockKey)
					table := "device_enrollments"
					if operation == repositoryWriterEnroll {
						table = "enrollment_challenges"
					}
					// The row insertion has happened, but this update must finish
					// before the repository can send COMMIT to PostgreSQL.
					if _, err := db.Exec(fmt.Sprintf(`CREATE FUNCTION block_writer() RETURNS trigger LANGUAGE plpgsql AS $$
						BEGIN PERFORM pg_advisory_xact_lock(%d); RETURN NEW; END $$;
						CREATE TRIGGER block_writer BEFORE UPDATE ON `+table+` FOR EACH ROW EXECUTE FUNCTION block_writer()`, repositoryWriterLockKey)); err != nil {
						t.Fatal(err)
					}
				}
				parsed, _ := url.Parse(databaseURL)
				query := parsed.Query()
				query.Set("application_name", repositoryWriterApplicationName)
				parsed.RawQuery = query.Encode()
				command := exec.Command(os.Args[0], "-test.run=^TestRepositoryWriterProcess$")
				command.Env = append(os.Environ(), repositoryWriterURLEnv+"="+parsed.String(), repositoryWriterOperationEnv+"="+operation)
				var stderr bytes.Buffer
				command.Stderr = &stderr
				stdout, err := command.StdoutPipe()
				if err != nil {
					t.Fatal(err)
				}
				stdin, err := command.StdinPipe()
				if err != nil {
					t.Fatal(err)
				}
				defer stdin.Close()
				if err := command.Start(); err != nil {
					t.Fatal(err)
				}
				defer command.Process.Kill()
				if committed {
					line := make(chan string, 1)
					go func() {
						text, _ := bufio.NewReader(stdout).ReadString('\n')
						line <- text
					}()
					select {
					case result := <-line:
						if result != repositoryWriterCommitted+"\n" {
							t.Fatalf("writer did not reach commit: %q", result)
						}
					case <-time.After(repositoryTestTimeout):
						t.Fatal("writer did not commit")
					}
				} else {
					waitRepositoryCondition(t, func(ctx context.Context) (bool, error) {
						var waiting bool
						err := db.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM pg_stat_activity
							WHERE datname=current_database() AND application_name=$1
							AND wait_event_type='Lock' AND wait_event='advisory')`, repositoryWriterApplicationName).Scan(&waiting)
						return waiting, err
					})
				}
				if err := command.Process.Kill(); err != nil {
					t.Fatal(err)
				}
				if err := command.Wait(); err == nil {
					t.Fatal("writer exited normally instead of being killed")
				}
				if stderr.Len() != 0 {
					t.Fatalf("writer failed before kill: %s", &stderr)
				}
				if blocker != nil {
					if _, err := blocker.ExecContext(context.Background(), `SELECT pg_advisory_unlock($1)`, repositoryWriterLockKey); err != nil {
						t.Fatal(err)
					}
				}
				waitRepositoryCondition(t, func(ctx context.Context) (bool, error) {
					var gone bool
					err := db.QueryRowContext(ctx, `SELECT NOT EXISTS (SELECT 1 FROM pg_stat_activity
						WHERE datname=current_database() AND application_name=$1)`, repositoryWriterApplicationName).Scan(&gone)
					return gone, err
				})
				if operation == repositoryWriterEvidence {
					if committed {
						requireRepositoryState(t, db, contracts.FirstEvidenceSequenceV1, 1)
					} else {
						requireRepositoryState(t, db, contracts.EnrollmentSequenceV1, 0)
					}
				} else {
					device, err := repo.Device(context.Background(), enrollment.DeviceID)
					var consumed bool
					if scanErr := db.QueryRow(`SELECT consumed_at IS NOT NULL FROM enrollment_challenges`).Scan(&consumed); scanErr != nil {
						t.Fatal(scanErr)
					}
					if committed {
						if err != nil || device.LastSequence != contracts.EnrollmentSequenceV1 || !consumed {
							t.Fatalf("committed enrollment incomplete: mark=%d consumed=%v err=%v", device.LastSequence, consumed, err)
						}
					} else if !errors.Is(err, ErrRepositoryNotFound) || consumed {
						t.Fatalf("killed enrollment survived: consumed=%v err=%v", consumed, err)
					}
				}
			})
		}
	}
}

func TestRepositoryPostgresCrashRecovery(t *testing.T) {
	if os.Getenv(repositoryRestartTestEnv) != "1" {
		t.Skip("TEST_POSTGRES_RESTART=1 enables a new isolated PostgreSQL cluster; never restarts TEST_DATABASE_URL")
	}
	for _, binary := range []string{"initdb", "pg_ctl"} {
		if _, err := exec.LookPath(binary); err != nil {
			t.Fatalf("storage-crash-check requires %s on PATH: %v", binary, err)
		}
	}
	root := t.TempDir()
	data, log := filepath.Join(root, "data"), filepath.Join(root, "postgres.log")
	run := func(args ...string) {
		t.Helper()
		command := exec.Command(args[0], args[1:]...)
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("%s: %v\n%s", args[0], err, output)
		}
	}
	run("initdb", "-D", data, "-A", "trust", "-U", "postgres", "--no-locale", "--encoding=UTF8")
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	options := fmt.Sprintf("-h 127.0.0.1 -p %d -c unix_socket_directories=''", port)
	run("pg_ctl", "-D", data, "-l", log, "-o", options, "-w", "start")
	t.Cleanup(func() {
		if output, err := exec.Command("pg_ctl", "-D", data, "-m", "immediate", "-w", "stop").CombinedOutput(); err != nil {
			t.Errorf("stop isolated cluster: %v %s", err, output)
		}
	})
	ctx := context.Background()
	databaseURL := fmt.Sprintf("postgres://postgres@127.0.0.1:%d/postgres?sslmode=disable", port)
	db, err := database.Open(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := database.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	var serverVersion, fsync, fullPageWrites string
	if err := db.QueryRow(`SELECT current_setting('server_version'), current_setting('fsync'), current_setting('full_page_writes')`).Scan(&serverVersion, &fsync, &fullPageWrites); err != nil {
		t.Fatal(err)
	}
	if fsync != "on" || fullPageWrites != "on" {
		t.Fatal("crash proof requires PostgreSQL durability settings")
	}
	t.Logf("isolated PostgreSQL %s, fsync=%s, full_page_writes=%s", serverVersion, fsync, fullPageWrites)
	// Force the session default off; repository writes must override it.
	if _, err := db.Exec(`ALTER DATABASE postgres SET synchronous_commit=off`); err != nil {
		t.Fatal(err)
	}
	db.Close()
	db, err = database.Open(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repo := fixtureRepository(t, db)
	enrollment := enrollRepositoryFixture(t, repo)
	_, evidence := repositoryEnvelopes(t)
	if err := repo.AcceptEvidence(ctx, evidence); err != nil {
		t.Fatal(err)
	}
	run("pg_ctl", "-D", data, "-m", "immediate", "-w", "stop")
	if err := repo.AcceptEvidence(ctx, evidence); !errors.Is(err, ErrRepositoryUnavailable) {
		t.Fatalf("database outage did not fail closed: %v", err)
	}
	run("pg_ctl", "-D", data, "-l", log, "-o", options, "-w", "start")
	db.Close()
	db, err = database.Open(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repo = fixtureRepository(t, db)
	requireRepositoryState(t, db, contracts.FirstEvidenceSequenceV1, 1)
	device, err := repo.Device(ctx, enrollment.DeviceID)
	if err != nil || device.Envelope.Signature != enrollment.Signature {
		t.Fatalf("identity provenance lost after PostgreSQL crash: %v", err)
	}
	stored, err := repo.Evidence(ctx, evidence.DeviceID, evidence.Sequence)
	if err != nil || stored.Envelope.Signature != evidence.Signature {
		t.Fatalf("evidence provenance lost after PostgreSQL crash: %v", err)
	}
	requireRepositoryRejection(t, repo.AcceptEvidence(ctx, evidence), contracts.EnvelopeRejectionReplay)
	requireRepositoryRejection(t, repo.Enroll(ctx, enrollment), contracts.EnvelopeRejectionChallengeReused)
	contents, err := os.ReadFile(log)
	if err != nil || !strings.Contains(string(contents), "database system was interrupted") {
		t.Fatalf("restart did not exercise PostgreSQL crash recovery: %v", err)
	}
	// Bootstrap's token and network tables must recover with the signed identity.
	token, err := repo.IssueBootstrapToken(ctx, contracts.BootstrapTokenRequestV1{SchemaVersion: contracts.BootstrapTokenRequestV1Version, DeviceID: "device:bootstrap-crash"}, "https://id.example.test", "admin:crash-test")
	if err != nil {
		t.Fatal(err)
	}
	keys := newEnrollmentKeys(t)
	challenge, err := repo.StartEnrollment(ctx, token.Token, contracts.EnrollmentStartV1{SchemaVersion: contracts.EnrollmentStartV1Version, DeploymentID: token.DeploymentID, DeviceID: token.DeviceID, PublicKey: hex.EncodeToString(keys.signing.Public().(ed25519.PublicKey)), NetworkPublicKey: hex.EncodeToString(keys.networkPublic[:])})
	if err != nil {
		t.Fatal(err)
	}
	clock := &enrollmentClock{}
	clock.seconds.Store(repo.now().Unix())
	request := admissionForChallenge(t, clock, challenge, keys)
	if _, err := repo.AdmitEnrollment(ctx, token.Token, request); err != nil {
		t.Fatal(err)
	}
	run("pg_ctl", "-D", data, "-m", "immediate", "-w", "stop")
	if _, err := repo.AdmitEnrollment(ctx, token.Token, request); !errors.Is(err, ErrRepositoryUnavailable) {
		t.Fatalf("bootstrap outage did not fail closed: %v", err)
	}
	run("pg_ctl", "-D", data, "-l", log, "-o", options, "-w", "start")
	db.Close()
	db, err = database.Open(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repo = fixtureRepository(t, db)
	binding, err := repo.NetworkBinding(ctx, token.DeviceID)
	if err != nil || binding.NetworkPublicKey != request.NetworkPublicKey || binding.SigningKeyID != request.Enrollment.SigningKeyID {
		t.Fatalf("bootstrap binding lost after crash: %v", err)
	}
	device, err = repo.Device(ctx, token.DeviceID)
	if err != nil || device.LastSequence != contracts.EnrollmentSequenceV1 {
		t.Fatalf("bootstrap signing state lost after crash: %v", err)
	}
	_, err = repo.AdmitEnrollment(ctx, token.Token, request)
	requireRepositoryRejection(t, err, contracts.EnvelopeRejectionBootstrapInvalid)
	requireRepositoryRejection(t, repo.Enroll(ctx, request.Enrollment), contracts.EnvelopeRejectionChallengeReused)
	t.Log("bootstrap signing/network binding, token consumption and challenge consumption survived abrupt PostgreSQL recovery")
}
