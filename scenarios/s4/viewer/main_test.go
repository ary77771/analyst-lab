package main

import (
	"strings"
	"testing"
)

func TestChainCommandLineRunsPowerShellOnTheScript(t *testing.T) {
	line, err := ChainCommandLine(`C:\Windows`, `D:\s4\s4_note.ps1`)
	if err != nil {
		t.Fatal(err)
	}
	want := `cmd.exe /d /c C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File D:\s4\s4_note.ps1`
	if line != want {
		t.Fatalf("got  %s\nwant %s", line, want)
	}
	if !strings.HasSuffix(line, `\s4_note.ps1`) {
		t.Fatal("the script must be the last word")
	}
}

func TestOnlyAPlainPs1PathIsAccepted(t *testing.T) {
	bad := []string{`D:\s4\note.exe`, `D:\s4\a b.ps1`, `D:\s4\x.ps1 & calc`, `D:\s4\x.ps1"`, `D:\s4\x|y.ps1`, `D:\s4\%x%.ps1`, ``, "D:\\s4\\a\tb.ps1", "D:\\s4\\x.ps1\ncalc", `s4\x.ps1`, `\\server\share\x.ps1`}
	for _, s := range bad {
		if _, err := ChainCommandLine(`C:\Windows`, s); err == nil {
			t.Fatalf("%q was accepted", s)
		}
	}
	if _, err := ChainCommandLine(``, `D:\s4\s4_note.ps1`); err == nil {
		t.Fatal("empty SystemRoot accepted")
	}
}
