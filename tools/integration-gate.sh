#!/bin/sh
# INT02 #31: run the same-host failure-path tests named in
# docs/validation/integration-gate-31.md against a disposable PostgreSQL.
# A skipped test fails the run, so a missing database cannot read as a pass.
# This is not the two-Windows-machine gate; it records no real-device result.
set -eu
: "${TEST_DATABASE_URL:?TEST_DATABASE_URL must name a disposable PostgreSQL database}"
GO=${GO:-go}
out=$(mktemp)
trap 'rm -f "$out"' EXIT

run() {
	pkg=$1
	pattern=$2
	"$GO" test -race -count=1 -v -run "$pattern" "$pkg" >>"$out" 2>&1 || {
		cat "$out" >&2
		echo "FAIL: $pkg $pattern" >&2
		exit 1
	}
}

run ./internal/controller '^(TestEnrollmentRejectsInvalidProofsAndExpiryWithoutAdmission|TestMeshAdmissionPersistsAndRevocationDenies|TestMeshConcurrentDuplicatesAcceptOnce|TestMeshSequencePolicySurvivesControllerRestart|TestRevocationRejectsFreshAndEstablishedPeersAcrossRestart|TestRevocationRejectsSampleQueuedBehindIt|TestDeviceStateHTTPPaginationProvenanceAndRestart|TestConsoleHistoryPageSurvivesRestart)$'
run ./apps/endpoint-agent '^(TestEndpointEnrollmentPostgres|TestEnrollmentAndProcessRestart|TestSpoolDrainKeepsUnacknowledgedHead|TestSpoolDrainBackoffAndOrdering)$'
run ./networking/mesh '^TestScopedRelayDirectAndRelayDelivery$'

if grep -q -e '--- SKIP' "$out"; then
	grep -e '--- SKIP' "$out" >&2
	echo "FAIL: a gate test was skipped" >&2
	exit 1
fi
echo "passed: $(grep -c -e '^--- PASS' "$out") top-level tests; none skipped"
