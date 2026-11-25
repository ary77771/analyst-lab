// s2_checkin: scenarios S2/S2J "regular check-ins" (harmless).
//
// Asks the lab's test server for a small text file -count times, -interval apart, opening a NEW
// connection each time (keep-alive off), waits -linger (5 s) so Sysmon can still name it in the
// last connection, then exits. With -jitter J each wait is
// interval x (1 +- J) at random, seeded by -seed so a run can be repeated. Nothing is written,
// nothing is run. Runs only inside the lab VM; talks only to the given test server.
package main

import (
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"time"
)

func main() {
	server := flag.String("server", "", "lab test server, e.g. http://10.0.2.2:18765 (required)")
	count := flag.Int("count", 10, "number of check-ins")
	interval := flag.Duration("interval", 30*time.Second, "time between check-ins")
	jitter := flag.Float64("jitter", 0, "each wait is interval x (1 +- jitter) at random, 0 <= jitter < 1")
	seed := flag.Int64("seed", 1, "random seed for the jitter (same seed = same waits)")
	linger := flag.Duration("linger", 5*time.Second, "wait after the last check-in before exiting")
	flag.Parse()

	if *server == "" || *count < 1 || *jitter < 0 || *jitter >= 1 || *interval <= 0 {
		fmt.Fprintln(os.Stderr, "s2_checkin: need -server, -count >= 1, -interval > 0, 0 <= -jitter < 1")
		os.Exit(2)
	}
	waits := Schedule(*count, *interval, *jitter, *seed)
	if err := run(*server, waits, time.Now, time.Sleep); err != nil {
		fmt.Fprintln(os.Stderr, "s2_checkin:", err)
		os.Exit(1)
	}
	// Sysmon reports a connection a moment after it happens and then looks up its program; a
	// program that has already exited can be reported as "<unknown process>" (review 2026-10-19).
	time.Sleep(*linger)
}

// Schedule returns the offset of every check-in from the start: 0, then each wait added.
// Offsets are planned up front, so a slow connection never pushes the later check-ins back.
func Schedule(count int, interval time.Duration, jitter float64, seed int64) []time.Duration {
	r := rand.New(rand.NewSource(seed))
	at := make([]time.Duration, count)
	for i := 1; i < count; i++ {
		f := 1.0
		if jitter > 0 {
			f = 1 + jitter*(2*r.Float64()-1)
		}
		at[i] = at[i-1] + time.Duration(float64(interval)*f)
	}
	return at
}

func run(server string, at []time.Duration, now func() time.Time, sleep func(time.Duration)) error {
	// A new connection per check-in, so Sysmon records each one (A13).
	client := &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{DisableKeepAlives: true}}
	start := now()
	for i, offset := range at {
		if d := start.Add(offset).Sub(now()); d > 0 {
			sleep(d)
		}
		resp, err := client.Get(server + "/s2_checkin.txt")
		if err != nil {
			return fmt.Errorf("check-in %d: %w", i+1, err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("check-in %d: HTTP %d", i+1, resp.StatusCode)
		}
		fmt.Printf("check-in %d/%d ok\n", i+1, len(at))
	}
	return nil
}
