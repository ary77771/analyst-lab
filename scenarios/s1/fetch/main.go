// s1_fetch: scenario S1 "download and run" (harmless).
//
// Downloads s1_payload.exe from the lab's test server, saves it under an \AnalystLab\ folder,
// runs it, waits for it to finish, and exits. The payload only prints a line.
// Runs only inside the lab VM; talks only to the given test server. It runs the download only
// if its SHA-256 equals -sha256 (the lab payload's, put on the scenario CD by
// make_scenario_cd.ps1), so it can never run anything else (independent review, 2026-10-17).
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

func main() {
	server := flag.String("server", "http://10.0.2.2:8765", "lab test server (host as seen from the VM)")
	out := flag.String("out", `C:\AnalystLab\scenarios\s1\payload\s1_payload.exe`, "where to save the payload")
	want := flag.String("sha256", "", "required SHA-256 of the payload; anything else is deleted, never run")
	flag.Parse()

	if *want == "" {
		fmt.Fprintln(os.Stderr, "s1_fetch: -sha256 is required (safety: only the lab's own payload may run)")
		os.Exit(2)
	}
	if err := run(*server, *out, strings.ToUpper(*want)); err != nil {
		fmt.Fprintln(os.Stderr, "s1_fetch:", err)
		os.Exit(1)
	}
}

func run(server, out, want string) error {
	// A new connection per request (no keep-alive), so Sysmon records each connection (A13).
	client := &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{DisableKeepAlives: true}}
	resp, err := client.Get(server + "/s1_payload.exe")
	if err != nil {
		return fmt.Errorf("download: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download: HTTP %d", resp.StatusCode)
	}

	if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
		return err
	}
	f, err := os.Create(out)
	if err != nil {
		return err
	}
	h := sha256.New()
	if _, err := io.Copy(io.MultiWriter(f, h), resp.Body); err != nil {
		f.Close()
		return fmt.Errorf("save: %w", err)
	}
	if err := f.Close(); err != nil {
		return err
	}
	if got := strings.ToUpper(hex.EncodeToString(h.Sum(nil))); got != want {
		os.Remove(out)
		return fmt.Errorf("payload fingerprint %s is not the lab payload's %s; deleted, not run", got, want)
	}
	fmt.Println("s1_fetch: saved", out, "(fingerprint verified)")

	cmd := exec.Command(out)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("run payload: %w", err)
	}
	fmt.Println("s1_fetch: payload finished")
	return nil
}
