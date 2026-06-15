package gateway

import (
	"io"
	"net"
	"sync"
)

func pipe(a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); io.Copy(a, b) }() //nolint:errcheck
	go func() { defer wg.Done(); io.Copy(b, a) }() //nolint:errcheck
	wg.Wait()
}
