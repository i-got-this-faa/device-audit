package database

import (
	"context"
	"testing"
	"testing/fstest"
)

func TestBootstrapUpgradePreservesSigningOnlyIdentityWithoutNetworkAdmission(t *testing.T) {
	db := openTestDatabase(t)
	prior := fstest.MapFS{}
	for _, name := range []string{"migrations/001_initial.sql", "migrations/002_console_auth.sql", "migrations/003_device_repository.sql"} {
		body, err := embeddedMigrations.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		prior[name] = &fstest.MapFile{Data: body}
	}
	if version, err := MigrateFS(context.Background(), db, prior); err != nil || version != 3 {
		t.Fatalf("install signing schema: %d %v", version, err)
	}
	if _, err := db.Exec(`INSERT INTO controller_deployments (deployment_id) VALUES ('deployment:prior');
		INSERT INTO enrollment_challenges (deployment_id,id,device_id,signing_key_id,authorization_reference,created_at,expires_at,consumed_at)
		VALUES ('deployment:prior',repeat('ab',32),'device:prior','ed25519:'||repeat('cd',32),'authorization:prior','2026-10-24T12:00:00Z','2026-10-24T12:10:00Z','2026-10-24T12:01:00Z');
		INSERT INTO device_enrollments (deployment_id,device_id,signing_key_id,public_key,challenge_id,envelope,request_sha256,enrolled_at,last_sequence)
		VALUES ('deployment:prior','device:prior','ed25519:'||repeat('cd',32),decode(repeat('ef',32),'hex'),repeat('ab',32),'{}',decode(repeat('ab',32),'hex'),'2026-10-24T12:01:00Z',42)`); err != nil {
		t.Fatal(err)
	}
	if version, err := Migrate(context.Background(), db); err != nil || version != 4 {
		t.Fatalf("bootstrap upgrade: %d %v", version, err)
	}
	var sequence int
	if err := db.QueryRow(`SELECT last_sequence FROM device_enrollments WHERE device_id='device:prior'`).Scan(&sequence); err != nil || sequence != 42 {
		t.Fatalf("upgrade changed signing state: %d %v", sequence, err)
	}
	var admitted, tokens int
	if err := db.QueryRow(`SELECT (SELECT count(*) FROM device_network_bindings),(SELECT count(*) FROM bootstrap_tokens)`).Scan(&admitted, &tokens); err != nil || admitted != 0 || tokens != 0 {
		t.Fatalf("signing-only rows silently admitted: %d %d %v", admitted, tokens, err)
	}
}
