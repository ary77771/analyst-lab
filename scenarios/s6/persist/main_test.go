package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// The tests never touch the real registry or Startup folder: setRun is a fake, folders are temp.
func setup(t *testing.T) (self, dir, startup string) {
	root := t.TempDir()
	self = filepath.Join(root, "s6_persist.exe")
	if err := os.WriteFile(self, []byte("MZ fake program"), 0o755); err != nil {
		t.Fatal(err)
	}
	return self, filepath.Join(root, "AnalystLab", "scenarios", "s6"),
		filepath.Join(root, "AppData", "Roaming", "Microsoft", "Windows", "Start Menu", "Programs", "Startup")
}

func TestCopiesItselfSetsRunValueAndWritesStartupScript(t *testing.T) {
	self, dir, startup := setup(t)
	var name, value string
	if err := Run(self, dir, startup, func(n, v string) error { name, value = n, v; return nil }); err != nil {
		t.Fatal(err)
	}
	copyPath := filepath.Join(dir, "s6_startup.exe")
	if got, _ := os.ReadFile(copyPath); string(got) != "MZ fake program" {
		t.Fatalf("copy has %q", got)
	}
	if name != "AnalystLab S6" || value != `"`+copyPath+`" -startup` {
		t.Fatalf("Run value %q = %q", name, value)
	}
	if got, _ := os.ReadFile(filepath.Join(startup, "analystlab_s6.cmd")); string(got) != ScriptText {
		t.Fatalf("startup script %q", got)
	}
}

func TestRefusesOtherFolders(t *testing.T) {
	self, dir, startup := setup(t)
	called := false
	fake := func(string, string) error { called = true; return nil }
	if Run(self, filepath.Join(filepath.Dir(dir), "s7"), startup, fake) == nil {
		t.Fatal("accepted a folder that is not ...\\scenarios\\s6")
	}
	if Run(self, `C:\ProgramData\AnalystLab\scenarios\s6`, startup, fake) == nil {
		t.Fatal("accepted the friend package's data folder")
	}
	if Run(self, dir, filepath.Dir(startup), fake) == nil {
		t.Fatal("accepted a folder that is not a Startup folder")
	}
	if called {
		t.Fatal("set a Run value although it refused")
	}
}

func TestStopsWhenTheRunValueFails(t *testing.T) {
	self, dir, startup := setup(t)
	if Run(self, dir, startup, func(string, string) error { return errors.New("denied") }) == nil {
		t.Fatal("no error")
	}
	if _, err := os.Stat(filepath.Join(startup, "analystlab_s6.cmd")); err == nil {
		t.Fatal("wrote the Startup script after the Run value failed")
	}
}
