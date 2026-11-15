//go:build unix

package consoletest

import (
	"strconv"
	"syscall"
	"testing"
)

// UnreachableURL returns a base URL whose connections are refused: its port
// is held by a socket that is bound but never listens, so no other process
// can take the port before the test is done with it, as one could take a
// free port released after it was found. The socket is closed when the test
// ends. A fixed low port such as 1, or port 0, is no substitute: on some
// hosts a connection to it times out rather than being refused.
//
// It is unix-only: it binds the socket through package syscall.
func UnreachableURL(t *testing.T) string {
	t.Helper()
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatalf("open a socket for the unreachable URL: %v", err)
	}
	t.Cleanup(func() {
		if cerr := syscall.Close(fd); cerr != nil {
			t.Errorf("close the unreachable URL's socket: %v", cerr)
		}
	})
	if err = syscall.Bind(fd, &syscall.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}}); err != nil {
		t.Fatalf("bind the unreachable URL's socket: %v", err)
	}
	sa, err := syscall.Getsockname(fd)
	if err != nil {
		t.Fatalf("read the unreachable URL's address: %v", err)
	}
	addr, ok := sa.(*syscall.SockaddrInet4)
	if !ok {
		t.Fatalf("unreachable URL bound to %T, want an IPv4 address", sa)
	}
	return "http://127.0.0.1:" + strconv.Itoa(addr.Port)
}
