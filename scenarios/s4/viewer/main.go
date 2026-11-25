// s4_viewer: scenario S4 "unusual program chain" (harmless).
//
// A document-viewer-like program that starts Windows' command shell, which starts PowerShell
// running a tiny script from the scenario CD (-script, default s4_note.ps1 next to this
// program). The script only prints one line and waits 2 s. Nothing is written, nothing is
// downloaded, no network. Waits for the chain to finish, lingers -linger (2 s), exits.
// Runs only inside the lab VM.
package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"syscall"
	"time"
)

func main() {
	self, _ := os.Executable()
	script := flag.String("script", filepath.Join(filepath.Dir(self), "s4_note.ps1"), "the harmless script to run")
	linger := flag.Duration("linger", 2*time.Second, "wait after the chain has finished")
	flag.Parse()

	if _, err := os.Stat(`C:\LabTools`); err != nil { // the lab VM's marker folder (as run_scenario.ps1 checks)
		fmt.Fprintln(os.Stderr, "s4_viewer: refused: this is not the lab VM")
		os.Exit(3)
	}
	line, err := ChainCommandLine(os.Getenv("SystemRoot"), *script)
	if err != nil {
		fmt.Fprintln(os.Stderr, "s4_viewer:", err)
		os.Exit(2)
	}
	if _, err := os.Stat(*script); err != nil {
		fmt.Fprintln(os.Stderr, "s4_viewer: script not found:", err)
		os.Exit(2)
	}
	cmd := exec.Command(filepath.Join(os.Getenv("SystemRoot"), "System32", "cmd.exe"))
	// The exact command line, so Sysmon records it as written (Go would otherwise re-quote it).
	cmd.SysProcAttr = &syscall.SysProcAttr{CmdLine: line}
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	fmt.Println("viewer: opening the shell")
	if err := cmd.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "s4_viewer: chain failed:", err)
		os.Exit(1)
	}
	time.Sleep(*linger)
}

// safeScript: a drive, then only letters, digits, _ . - and backslashes, ending in .ps1. An
// ALLOW list (review 2026-10-19: a block list missed tabs and newlines), so the line can't be
// bent into running anything else and the script stays the last word.
var safeScript = regexp.MustCompile(`^[A-Za-z]:\\[A-Za-z0-9_.\\-]+\.[pP][sS]1$`)

// ChainCommandLine is cmd.exe's command line: run PowerShell on the script, then return. /d: skip
// any AutoRun commands configured for cmd.exe, so only this chain runs.
func ChainCommandLine(systemRoot, script string) (string, error) {
	if systemRoot == "" {
		return "", fmt.Errorf("SystemRoot is not set")
	}
	if !safeScript.MatchString(script) {
		return "", fmt.Errorf("refusing script %q: a plain .ps1 path (letters, digits, _ . -) only", script)
	}
	ps := filepath.Join(systemRoot, "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
	return fmt.Sprintf(`cmd.exe /d /c %s -NoProfile -NonInteractive -ExecutionPolicy Bypass -File %s`, ps, script), nil
}
