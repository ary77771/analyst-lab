// s6_persist: scenario S6 "persistence" (harmless, version 2).
//
// It copies itself to C:\AnalystLab\scenarios\s6\s6_startup.exe and makes that copy start at
// the next logon in the two most common ways (MITRE ATT&CK T1547.001): a value "AnalystLab S6"
// under the user's Run key, and analystlab_s6.cmd (it only prints a line) in the user's Startup
// folder. The VM is restored to its clean snapshot after every run, so no logon ever follows.
// Started with -startup (what the Run value says) it only prints a line and exits.
// No network, starts nothing, normal user rights (HKCU only). Runs only inside the lab VM.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

const (
	ValueName  = "AnalystLab S6"
	ScriptName = "analystlab_s6.cmd"
	ScriptText = "@echo Analyst Lab scenario S6: a harmless startup script.\r\n"
	runKey     = `Software\Microsoft\Windows\CurrentVersion\Run`
)

func main() {
	startup := flag.Bool("startup", false, "the mode the autostart entries use: print a line and exit")
	dir := flag.String("dir", `C:\AnalystLab\scenarios\s6`, "where the copy goes (must be ...\\AnalystLab\\scenarios\\s6)")
	linger := flag.Duration("linger", 2*time.Second, "wait before exiting")
	flag.Parse()

	if *startup {
		fmt.Println("Analyst Lab scenario S6: started at logon (harmless)")
		return
	}
	if _, err := os.Stat(`C:\LabTools`); err != nil { // the lab VM's marker folder (as run_scenario.ps1 checks)
		fmt.Fprintln(os.Stderr, "s6_persist: refused: this is not the lab VM")
		os.Exit(3)
	}
	self, err := os.Executable()
	if err != nil {
		fmt.Fprintln(os.Stderr, "s6_persist:", err)
		os.Exit(1)
	}
	startupDir := filepath.Join(os.Getenv("APPDATA"), `Microsoft\Windows\Start Menu\Programs\Startup`)
	if err := Run(self, *dir, startupDir, setRunValue); err != nil {
		fmt.Fprintln(os.Stderr, "s6_persist:", err)
		os.Exit(1)
	}
	time.Sleep(*linger)
}

// Run copies `self` into dir, sets the Run value (through setRun) and writes the Startup script.
func Run(self, dir, startupDir string, setRun func(name, value string) error) error {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	if !strings.HasSuffix(strings.ToLower(abs), `\analystlab\scenarios\s6`) || strings.HasPrefix(strings.ToLower(abs), `c:\programdata`) {
		return fmt.Errorf("refusing %q: S6 copies itself only to ...\\AnalystLab\\scenarios\\s6", dir)
	}
	if !strings.HasSuffix(strings.ToLower(startupDir), `\start menu\programs\startup`) {
		return fmt.Errorf("refusing %q: not a Startup folder", startupDir)
	}
	data, err := os.ReadFile(self)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(abs, 0o755); err != nil {
		return err
	}
	copyPath := filepath.Join(abs, "s6_startup.exe")
	if err := os.WriteFile(copyPath, data, 0o755); err != nil {
		return err
	}
	fmt.Println("copied itself")
	if err := setRun(ValueName, `"`+copyPath+`" -startup`); err != nil {
		return err
	}
	fmt.Println("set the Run value")
	if err := os.MkdirAll(startupDir, 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(startupDir, ScriptName), []byte(ScriptText), 0o644); err != nil {
		return err
	}
	fmt.Println("wrote the Startup script")
	return nil
}

var regSetValueExW = syscall.NewLazyDLL("advapi32.dll").NewProc("RegSetValueExW")

// setRunValue writes a REG_SZ value under HKCU\...\Run (Windows API; the standard library has
// no registry writer, and golang.org/x/sys would be a new download for one call). The key is
// OPENED, not created: it exists in every Windows profile, and RegCreateKeyEx would add a Sysmon
// "CreateKey" event (12) the answer sheet does not expect (review 2026-11-07).
func setRunValue(name, value string) error {
	const hkeyCurrentUser, keySetValue, regSZ = 0x80000001, 0x0002, 1
	var key syscall.Handle
	sub, _ := syscall.UTF16PtrFromString(runKey)
	if err := syscall.RegOpenKeyEx(syscall.Handle(hkeyCurrentUser), sub, 0, keySetValue, &key); err != nil {
		return fmt.Errorf("open Run key: %v", err)
	}
	defer syscall.RegCloseKey(key)
	n, _ := syscall.UTF16PtrFromString(name)
	v, _ := syscall.UTF16FromString(value)
	if r, _, _ := regSetValueExW.Call(uintptr(key), uintptr(unsafe.Pointer(n)), 0, regSZ,
		uintptr(unsafe.Pointer(&v[0])), uintptr(len(v)*2)); r != 0 {
		return fmt.Errorf("set Run value: error %d", r)
	}
	return nil
}
