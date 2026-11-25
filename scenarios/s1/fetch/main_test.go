package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A download whose fingerprint isn't the lab payload's is deleted and never run.
// (Only the mismatch path is tested here: the match path runs the payload, which happens only
// inside the VM, per the lab's safety rule.)
func TestWrongFingerprintIsDeletedAndNotRun(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("not the lab payload"))
	}))
	defer srv.Close()
	out := filepath.Join(t.TempDir(), "s1_payload.exe")

	err := run(srv.URL, out, strings.Repeat("AB", 32))
	if err == nil || !strings.Contains(err.Error(), "not run") {
		t.Fatalf("expected a refusal, got %v", err)
	}
	if _, statErr := os.Stat(out); !os.IsNotExist(statErr) {
		t.Fatalf("the rejected download was not deleted")
	}
}
