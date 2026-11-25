// s3_listen: scenario S3 "unexpected listener" (harmless).
//
// Opens a listening TCP port on -addr (default 127.0.0.1:47213: reachable only from inside the
// VM, so no firewall prompt), keeps it open for -hold (60 s) WITHOUT accepting anyone, closes it,
// waits -linger (3 s) and exits. No connection is made or accepted, nothing is written, nothing
// is run. The lab sees it only through the agent's port snapshots (Sysmon has no "listening"
// event, assumption A11). Runs only inside the lab VM.
package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:47213", "where to listen (loopback only)")
	hold := flag.Duration("hold", 60*time.Second, "how long the port stays open")
	linger := flag.Duration("linger", 3*time.Second, "wait after closing the port before exiting")
	flag.Parse()

	if err := run(*addr, *hold, time.Sleep); err != nil {
		fmt.Fprintln(os.Stderr, "s3_listen:", err)
		os.Exit(1)
	}
	time.Sleep(*linger)
}

// run listens on addr for hold, then closes the port. Only loopback addresses are allowed:
// the scenario must never be reachable from outside the machine.
func run(addr string, hold time.Duration, sleep func(time.Duration)) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("bad -addr %q: %w", addr, err)
	}
	if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("refusing %q: S3 listens on a loopback address only", addr)
	}
	if hold <= 0 {
		return fmt.Errorf("-hold must be > 0")
	}
	ln, err := net.Listen("tcp4", addr)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	fmt.Printf("listening on %s for %v\n", ln.Addr(), hold)
	// Nobody is accepted: the listener only exists. (Accept is never called, so a client that
	// connected anyway would wait in the queue until the port closes.)
	sleep(hold)
	if err := ln.Close(); err != nil && !strings.Contains(err.Error(), "closed") {
		return fmt.Errorf("close: %w", err)
	}
	fmt.Println("port closed")
	return nil
}
