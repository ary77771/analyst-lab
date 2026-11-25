// s5_churn: scenario S5 "file churn" (harmless).
//
// In its own work folder (-dir, which must be under an \AnalystLab\ folder) it creates -count
// small dummy text files, waits -settle (10 s, so the lab's agent can fingerprint them), writes
// a copy of each with a new ending (.txt.s5copy, same dummy text), then deletes the originals.
// Nothing outside -dir is touched, nothing is run, no network. Runs only inside the lab VM.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func main() {
	dir := flag.String("dir", `C:\AnalystLab\scenarios\s5\work`, "work folder (must be under an \\AnalystLab\\ folder)")
	count := flag.Int("count", 40, "number of dummy files")
	settle := flag.Duration("settle", 10*time.Second, "wait between creating the originals and copying them")
	linger := flag.Duration("linger", 2*time.Second, "wait before exiting")
	flag.Parse()

	if _, err := os.Stat(`C:\LabTools`); err != nil { // the lab VM's marker folder (as run_scenario.ps1 checks)
		fmt.Fprintln(os.Stderr, "s5_churn: refused: this is not the lab VM")
		os.Exit(3)
	}
	if err := Run(*dir, *count, *settle, time.Sleep); err != nil {
		fmt.Fprintln(os.Stderr, "s5_churn:", err)
		os.Exit(1)
	}
	time.Sleep(*linger)
}

// Names of the originals: note_01.txt ... note_NN.txt.
func Names(count int) []string {
	out := make([]string, count)
	for i := range out {
		out[i] = fmt.Sprintf("note_%02d.txt", i+1)
	}
	return out
}

// Run does the three phases: create originals, (settle), write copies, delete originals.
func Run(dir string, count int, settle time.Duration, sleep func(time.Duration)) error {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	// exactly the scenario's own work folder (review 2026-10-19: "any \AnalystLab\ folder" would
	// also have accepted e.g. C:\ProgramData\AnalystLab, the friend package's data folder)
	if !strings.HasSuffix(strings.ToLower(abs), `\analystlab\scenarios\s5\work`) || strings.HasPrefix(strings.ToLower(abs), `c:\programdata`) {
		return fmt.Errorf("refusing %q: S5 works only in ...\\AnalystLab\\scenarios\\s5\\work", dir)
	}
	if count < 1 || count > 1000 {
		return fmt.Errorf("-count must be 1-1000")
	}
	if err := os.MkdirAll(abs, 0o755); err != nil {
		return err
	}
	names := Names(count)
	for i, n := range names {
		text := fmt.Sprintf("Analyst Lab scenario S5 dummy file %d of %d. Nothing to see here.\r\n", i+1, count)
		if err := os.WriteFile(filepath.Join(abs, n), []byte(text), 0o644); err != nil {
			return err
		}
	}
	fmt.Printf("created %d originals\n", count)
	sleep(settle)
	for _, n := range names {
		data, err := os.ReadFile(filepath.Join(abs, n))
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(abs, n+".s5copy"), data, 0o644); err != nil {
			return err
		}
	}
	fmt.Printf("wrote %d copies\n", count)
	for _, n := range names {
		if err := os.Remove(filepath.Join(abs, n)); err != nil {
			return err
		}
	}
	fmt.Printf("deleted %d originals\n", count)
	return nil
}
