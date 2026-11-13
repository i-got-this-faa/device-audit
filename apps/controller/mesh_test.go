package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAdminHTTPSExcludesDeviceApplicationPaths(t *testing.T) {
	h := adminOnly(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	for _, path := range []string{"/v1/evidence", "/v1/telemetry", "/v1/devices/test"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("POST", path, nil))
		if w.Code != 404 {
			t.Fatalf("public application path %s status=%d", path, w.Code)
		}
	}
	for _, path := range []string{"/healthz", "/admin/bootstrap-tokens", "/v1/enrollment", "/auth/login", "/inventory"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("POST", path, nil))
		if w.Code != 204 {
			t.Fatalf("administrator/bootstrap path blocked: %s", path)
		}
	}
}
