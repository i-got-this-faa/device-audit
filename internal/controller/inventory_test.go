package controller

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/i-got-this-faa/device-audit/infra/database"
	"github.com/i-got-this-faa/device-audit/internal/controller/auth"
	"github.com/i-got-this-faa/device-audit/packages/contracts"
)

func inventoryUpdate(device string, now time.Time) contracts.InventoryUpdateV1 {
	return contracts.InventoryUpdateV1{SchemaVersion: contracts.InventoryUpdateV1Version, DeviceID: device,
		ObservedAt: now, SourceReference: "observation:test", Inventory: contracts.InventoryV2{
			GroupID: "group:it", NetworkSegmentID: "segment:office", Components: []contracts.ComponentV2{{ID: "component:disk", Type: "storage", Model: "fixture-model"}}}}
}

func TestInventoryHistoryProvenanceAndReopen(t *testing.T) {
	db, databaseURL := openRepositoryTestDB(t)
	repo := fixtureRepository(t, db)
	enrolled := enrollRepositoryFixture(t, repo)
	update := inventoryUpdate(enrolled.DeviceID, repo.now())
	first, err := repo.UpdateInventory(context.Background(), update, "https://id.example.test", "admin:one")
	if err != nil {
		t.Fatal(err)
	}
	device, err := repo.Device(context.Background(), enrolled.DeviceID)
	if err != nil {
		t.Fatal(err)
	}
	if first.Revision != 1 || first.EnrollmentSHA256 != device.RequestSHA256 || first.ActorSubject != "admin:one" || device.LastSequence != 1 {
		t.Fatalf("lost provenance or changed evidence sequence: %+v %+v", first, device)
	}
	update.ExpectedRevision = 1
	update.Inventory = contracts.InventoryV2{Components: []contracts.ComponentV2{}}
	second, err := repo.UpdateInventory(context.Background(), update, "https://id.example.test", "admin:two")
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := database.Open(context.Background(), databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	repo = fixtureRepository(t, reopened)
	for _, test := range []struct {
		revision uint64
		want     contracts.InventoryRecordV1
	}{{1, first}, {2, second}, {0, second}} {
		got, err := repo.Inventory(context.Background(), enrolled.DeviceID, test.revision)
		if err != nil || !reflect.DeepEqual(got, test.want) {
			t.Fatalf("revision %d: got=%+v want=%+v err=%v", test.revision, got, test.want, err)
		}
	}
	if _, err := repo.UpdateInventory(context.Background(), update, "https://id.example.test", "admin:stale"); !errors.Is(err, ErrInventoryConflict) {
		t.Fatalf("stale update: %v", err)
	}
}

func TestInventoryRejectsUnknownRevokedInvalidAndConcurrentUpdates(t *testing.T) {
	db, databaseURL := openRepositoryTestDB(t)
	repo := fixtureRepository(t, db)
	update := inventoryUpdate("device:unknown", repo.now())
	if _, err := repo.UpdateInventory(context.Background(), update, "issuer", "subject"); !errors.Is(err, ErrRepositoryNotFound) {
		t.Fatalf("unknown update: %v", err)
	}
	if _, err := repo.Inventory(context.Background(), update.DeviceID, 0); !errors.Is(err, ErrRepositoryNotFound) {
		t.Fatalf("unknown read: %v", err)
	}
	enrolled := enrollRepositoryFixture(t, repo)
	update.DeviceID = enrolled.DeviceID
	for _, change := range []func(*contracts.InventoryUpdateV1){
		func(u *contracts.InventoryUpdateV1) { u.Inventory.Components[0].ID = "" },
		func(u *contracts.InventoryUpdateV1) { u.ObservedAt = u.ObservedAt.Add(time.Second) },
	} {
		invalid := inventoryUpdate(enrolled.DeviceID, repo.now())
		change(&invalid)
		if _, err := repo.UpdateInventory(context.Background(), invalid, "issuer", "subject"); !errors.Is(err, ErrInventoryInvalid) {
			t.Fatalf("invalid accepted: %v", err)
		}
	}
	otherDB, err := database.Open(context.Background(), databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer otherDB.Close()
	other := fixtureRepository(t, otherDB)
	results := make(chan error, 2)
	var wg sync.WaitGroup
	gate := make(chan struct{})
	for _, writer := range []*PostgresRepository{repo, other} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-gate
			_, err := writer.UpdateInventory(context.Background(), update, "issuer", "subject")
			results <- err
		}()
	}
	close(gate)
	wg.Wait()
	close(results)
	success, conflicts := 0, 0
	for err := range results {
		if err == nil {
			success++
		} else if errors.Is(err, ErrInventoryConflict) {
			conflicts++
		} else {
			t.Fatal(err)
		}
	}
	if success != 1 || conflicts != 1 {
		t.Fatalf("success=%d conflicts=%d", success, conflicts)
	}
	if _, err := db.Exec(`UPDATE device_enrollments SET revoked_at=now()`); err != nil {
		t.Fatal(err)
	}
	update.ExpectedRevision = 1
	if _, err := repo.UpdateInventory(context.Background(), update, "issuer", "subject"); !errors.Is(err, ErrInventoryRevoked) {
		t.Fatalf("revoked update: %v", err)
	}
	got, err := repo.Inventory(context.Background(), enrolled.DeviceID, 0)
	if err != nil || got.Revision != 1 {
		t.Fatalf("denied updates altered history: %+v %v", got, err)
	}
}

func TestInventoryRollbackAndUnavailableStore(t *testing.T) {
	db, _ := openRepositoryTestDB(t)
	repo := fixtureRepository(t, db)
	enrolled := enrollRepositoryFixture(t, repo)
	update := inventoryUpdate(enrolled.DeviceID, repo.now())
	if _, err := db.Exec(`CREATE FUNCTION reject_inventory_commit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected commit failure'; END $$;
		CREATE CONSTRAINT TRIGGER reject_inventory_commit AFTER INSERT ON inventory_revisions DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION reject_inventory_commit()`); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.UpdateInventory(context.Background(), update, "issuer", "subject"); !errors.Is(err, ErrRepositoryUnavailable) {
		t.Fatalf("failed commit accepted: %v", err)
	}
	if _, err := repo.Inventory(context.Background(), enrolled.DeviceID, 0); !errors.Is(err, ErrRepositoryNotFound) {
		t.Fatalf("failed commit retained revision: %v", err)
	}
	if _, err := db.Exec(`DROP TRIGGER reject_inventory_commit ON inventory_revisions`); err != nil {
		t.Fatal(err)
	}
	if record, err := repo.UpdateInventory(context.Background(), update, "issuer", "subject"); err != nil || record.Revision != 1 {
		t.Fatalf("rollback consumed revision: %+v %v", record, err)
	}
	db.Close()
	if _, err := repo.UpdateInventory(context.Background(), update, "issuer", "subject"); !errors.Is(err, ErrRepositoryUnavailable) {
		t.Fatalf("closed write: %v", err)
	}
	if _, err := repo.Inventory(context.Background(), enrolled.DeviceID, 0); !errors.Is(err, ErrRepositoryUnavailable) {
		t.Fatalf("closed read: %v", err)
	}
}

func TestInventoryHTTPAuthorizationAndQueries(t *testing.T) {
	b := newEnrollmentTestBed(t)
	token := b.issue(t, "device:inventory")
	keys := newEnrollmentKeys(t)
	challenge := b.challenge(t, token, keys)
	b.submit(t, token, admissionForChallenge(t, b.clock, challenge, keys), http.StatusCreated)
	service, err := NewInventoryService(b.repo, b.admin)
	if err != nil {
		t.Fatal(err)
	}
	handler := NewAPI(Config{MaxDevices: 1, Auth: b.admin, Inventory: service}).Handler()
	viewer, viewerCSRF := b.addSession(t, "viewer:test", auth.RoleViewer, 0)
	oldAdmin, oldCSRF := b.addSession(t, "admin:old", auth.RoleAdmin, 6*time.Minute)
	update := inventoryUpdate(token.DeviceID, b.clock.Now())
	encoded, _ := json.Marshal(update)
	path := "/console/api/devices/" + token.DeviceID + "/inventory"
	call := func(method, target, body, session, csrf, origin string, want int) []byte {
		t.Helper()
		r := httptest.NewRequest(method, target, strings.NewReader(body))
		r.Header.Set("Accept", "application/json")
		r.Header.Set("Content-Type", "application/json")
		if session != "" {
			r.AddCookie(&http.Cookie{Name: "__Host-device-audit-session", Value: session})
		}
		r.Header.Set("X-CSRF-Token", csrf)
		r.Header.Set("Origin", origin)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != want || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("%s %s: %d want %d: %s", method, target, w.Code, want, w.Body.String())
		}
		return w.Body.Bytes()
	}
	for _, method := range []string{"GET", "PUT"} {
		call(method, path, string(encoded), "", "", "", 401)
	}
	call("PUT", path, string(encoded), viewer, viewerCSRF, "https://console.example.test", 403)
	call("PUT", path, string(encoded), oldAdmin, oldCSRF, "https://console.example.test", 403)
	call("PUT", path, string(encoded), b.session, "wrong", "https://console.example.test", 403)
	call("PUT", path, string(encoded), b.session, b.csrf, "https://attacker.example", 403)
	call("GET", path, "", viewer, "", "", 404)
	call("PUT", strings.Replace(path, token.DeviceID, "device:other", 1), string(encoded), b.session, b.csrf, "https://console.example.test", 400)
	unknown := update
	unknown.DeviceID = "device:unknown"
	unknownBytes, _ := json.Marshal(unknown)
	call("PUT", strings.Replace(path, token.DeviceID, unknown.DeviceID, 1), string(unknownBytes), b.session, b.csrf, "https://console.example.test", 404)
	for _, bad := range []string{string(encoded) + "{}", strings.Repeat(" ", 64<<10) + string(encoded), strings.Replace(string(encoded), `"device_id":`, `"device_id":"wrong","device_id":`, 1), strings.Replace(string(encoded), `"inventory":`, `"actor_subject":"forged","inventory":`, 1)} {
		call("PUT", path, bad, b.session, b.csrf, "https://console.example.test", 400)
	}
	data := call("PUT", path, string(encoded), b.session, b.csrf, "https://console.example.test", 201)
	var record contracts.InventoryRecordV1
	if err := json.Unmarshal(data, &record); err != nil {
		t.Fatal(err)
	}
	if record.ActorSubject != "admin:test" || record.Revision != 1 {
		t.Fatalf("forged provenance: %+v", record)
	}
	call("PUT", path, string(encoded), b.session, b.csrf, "https://console.example.test", 409)
	for _, suffix := range []string{"", "?revision=1"} {
		data := call("GET", path+suffix, "", viewer, "", "", 200)
		var got contracts.InventoryRecordV1
		if err := json.Unmarshal(data, &got); err != nil || !reflect.DeepEqual(got, record) {
			t.Fatalf("read: %+v %v", got, err)
		}
	}
	for _, suffix := range []string{"?revision=0", "?revision=-1", "?revision=1&revision=2", "?other=x", "?revision=%zz", "?", "?revision=9007199254740992"} {
		call("GET", path+suffix, "", viewer, "", "", 400)
	}
	call("GET", path+"?revision=2", "", viewer, "", "", 404)
	if _, err := b.db.Exec(`UPDATE console_sessions SET idle_expires_at=$1`, b.clock.Now()); err != nil {
		t.Fatal(err)
	}
	data = call("GET", path, "", viewer, "", "", 401)
	if strings.Contains(string(data), record.DeviceID) || strings.Contains(string(data), record.SourceReference) {
		t.Fatal("expired read leaked inventory")
	}
}
