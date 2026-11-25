package main

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func TestScheduleWithoutJitterIsExact(t *testing.T) {
	at := Schedule(10, 30*time.Second, 0, 1)
	for i, a := range at {
		if a != time.Duration(i)*30*time.Second {
			t.Fatalf("check-in %d at %v, want %v", i+1, a, time.Duration(i)*30*time.Second)
		}
	}
}

func TestScheduleJitterStaysInRangeAndRepeats(t *testing.T) {
	at := Schedule(200, 30*time.Second, 0.4, 7)
	varied := false
	for i := 1; i < len(at); i++ {
		gap := at[i] - at[i-1]
		if gap < 18*time.Second || gap > 42*time.Second {
			t.Fatalf("gap %d = %v, outside 18-42 s", i, gap)
		}
		if gap != 30*time.Second {
			varied = true
		}
	}
	if !varied {
		t.Fatal("jitter produced no variation")
	}
	again := Schedule(200, 30*time.Second, 0.4, 7)
	for i := range at {
		if at[i] != again[i] {
			t.Fatal("same seed gave a different schedule")
		}
	}
}

func TestEachCheckInIsANewConnection(t *testing.T) {
	var mu sync.Mutex
	conns := map[string]bool{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		conns[r.RemoteAddr] = true // a new client port = a new TCP connection
		mu.Unlock()
		if r.URL.Path != "/s2_checkin.txt" {
			http.NotFound(w, r)
			return
		}
		w.Write([]byte("ok"))
	}))
	defer srv.Close()
	if err := run(srv.URL, Schedule(5, time.Millisecond, 0, 1), time.Now, time.Sleep); err != nil {
		t.Fatal(err)
	}
	if len(conns) != 5 {
		t.Fatalf("%d distinct connections for 5 check-ins, want 5 (keep-alive must be off)", len(conns))
	}
}

func TestServerErrorStopsTheRun(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()
	if err := run(srv.URL, Schedule(3, time.Millisecond, 0, 1), time.Now, time.Sleep); err == nil {
		t.Fatal("a 404 must fail the run (the scenario must not pretend it checked in)")
	}
}
