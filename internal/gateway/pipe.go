package gateway

import (
	"io"
	"net"
	"sync"
)

// pipe does a bidirectional copy between a and b.
// When either direction terminates, both connections are closed so the other
// direction unblocks and the goroutines can exit cleanly.
func pipe(a, b net.Conn) {
	var once sync.Once
	closeAll := func() {
		once.Do(func() {
			a.Close() //nolint:errcheck
			b.Close() //nolint:errcheck
		})
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); defer closeAll(); io.Copy(a, b) }() //nolint:errcheck
	go func() { defer wg.Done(); defer closeAll(); io.Copy(b, a) }() //nolint:errcheck
	wg.Wait()
}
