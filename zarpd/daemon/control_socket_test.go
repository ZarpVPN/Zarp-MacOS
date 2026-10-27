package daemon

import (
	"net"
	"testing"
)

func TestControlSocketFamily(t *testing.T) {
	for _, v6 := range []bool{false, true} {
		conn, err := listenControlUDP(v6)
		if err != nil {
			t.Fatal(err)
		}
		addr := conn.LocalAddr().(*net.UDPAddr)
		if (addr.IP.To4() == nil) != v6 {
			t.Errorf("wrong socket family for v6=%v", v6)
		}
		conn.Close()
	}
}
