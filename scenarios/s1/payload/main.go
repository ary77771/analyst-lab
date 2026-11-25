// s1_payload: the "downloaded program" of scenario S1. Completely harmless:
// it prints one line, waits 2 seconds (so Sysmon sees it running), and exits.
package main

import (
	"fmt"
	"time"
)

func main() {
	fmt.Println("s1_payload: harmless lab payload, exiting in 2 s")
	time.Sleep(2 * time.Second)
}
