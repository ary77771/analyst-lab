package main

import (
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"
)

func TestChurnLeavesOnlyCopiesWithTheSameText(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "AnalystLab", "scenarios", "s5", "work")
	settled := false
	if err := Run(dir, 5, 10*time.Second, func(time.Duration) { settled = true }); err != nil {
		t.Fatal(err)
	}
	if !settled {
		t.Fatal("no settle pause between creating and copying")
	}
	entries, _ := os.ReadDir(dir)
	var got []string
	for _, e := range entries {
		got = append(got, e.Name())
	}
	sort.Strings(got)
	want := []string{"note_01.txt.s5copy", "note_02.txt.s5copy", "note_03.txt.s5copy", "note_04.txt.s5copy", "note_05.txt.s5copy"}
	if len(got) != len(want) {
		t.Fatalf("files %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("files %v, want %v", got, want)
		}
	}
	b, _ := os.ReadFile(filepath.Join(dir, "note_03.txt.s5copy"))
	if string(b) != "Analyst Lab scenario S5 dummy file 3 of 5. Nothing to see here.\r\n" {
		t.Fatalf("copy text %q", b)
	}
}

func TestRefusesFoldersOutsideAnalystLab(t *testing.T) {
	for _, d := range []string{t.TempDir(), filepath.Join(t.TempDir(), "AnalystLabX", "w"),
		filepath.Join(t.TempDir(), "AnalystLab", "w"),                                   // any \AnalystLab\ folder: no
		filepath.Join(t.TempDir(), "AnalystLabX", "scenarios", "s5", "work"),            // look-alike name
		`C:\ProgramData\AnalystLab\scenarios\s5\work`,                                   // the friend package's data
		filepath.Join(t.TempDir(), "AnalystLab", "scenarios", "s5", "work", "deeper")} { // below the work folder
		if err := Run(d, 3, 0, func(time.Duration) {}); err == nil {
			t.Fatalf("%s was accepted", d)
		}
	}
}

func TestCountLimits(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "AnalystLab", "scenarios", "s5", "work")
	for _, n := range []int{0, -1, 1001} {
		if err := Run(dir, n, 0, func(time.Duration) {}); err == nil {
			t.Fatalf("count %d accepted", n)
		}
	}
}
