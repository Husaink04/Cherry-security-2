package app

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHealthAndUnavailableDatabase(t *testing.T) {
	handler := New(nil, Config{Origin: "http://127.0.0.1:8080"})
	for path, want := range map[string]int{"/api/healthz": 200, "/api/readyz": 503} {
		request := httptest.NewRequest(http.MethodGet, path, nil)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != want {
			t.Fatalf("%s: got %d want %d", path, response.Code, want)
		}
	}
}

func TestDatabaseSchemaCompatibility(t *testing.T) {
	db, _, _, _ := setupIntegration(t)
	if err := CheckSchema(context.Background(), db); err != nil { t.Fatal(err) }
	if _, err := db.Exec(context.Background(), "INSERT INTO schema_migrations(version) VALUES($1)", SchemaVersion+1); err != nil { t.Fatal(err) }
	if CheckSchema(context.Background(), db) == nil { t.Fatal("future schema must prevent application startup") }
}
