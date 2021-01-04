package client

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"strings"
	"testing"

	"github.com/luyuhuang/subsocks/utils"
)

func TestHTTPWrapper(t *testing.T) {
	cases := []struct {
		path string
		data []string
		res  []string
	}{
		{"/", []string{"asdf"}, []string{"cdef"}},
		{"/proxy", []string{"asdf", "acde", "xxx"}, []string{"cdef", "cd"}},
		{"/a/b", []string{"asdf", "acde", "xxx"}, []string{"cdef", "cd"}},
	}

	for _, c := range cases {
		addr, _ := net.ResolveIPAddr("tcp", "127.0.0.1:1030")
		conn := utils.NewFakeConn(addr, addr)

		cli := NewClient("127.0.0.1:1030")
		cli.Config.HTTPPath = c.path

		wrapper := newHTTPWrapper(conn, cli)
		for _, datum := range c.data {
			wrapper.Write([]byte(datum))
		}

		req, err := http.ReadRequest(bufio.NewReader(conn.Out))
		if err != nil {
			t.Fatalf("Parse request failed: %s", err)
		}
		if req.URL.Path != c.path {
			t.Fatalf("Request path got %q, want %q", req.URL.Path, c.path)
		}

		joinedData := strings.Join(c.data, "")
		buf := make([]byte, len(joinedData)*2)
		n, err := req.Body.Read(buf)
		if err != nil {
			t.Fatalf("Read from body failed: %s", err)
		}
		if string(buf[:n]) != joinedData {
			t.Fatalf("Read got %q, want %q", string(buf[:n]), joinedData)
		}

		conn.In.WriteString("HTTP/1.1 200 OK\r\n")
		conn.In.WriteString("Transfer-Encoding: chunked\r\n")
		conn.In.WriteString("\r\n")
		for _, datum := range c.res {
			conn.In.WriteString(fmt.Sprintf("%X\r\n", len(datum)))
			conn.In.WriteString(datum)
			conn.In.WriteString("\r\n")
		}

		joinedRes := strings.Join(c.res, "")
		buf = make([]byte, len(joinedRes)*2)
		n, err = wrapper.Read(buf)
		if err != nil {
			t.Fatalf("Read response failed: %s", err)
		}
		if string(buf[:n]) != joinedRes {
			t.Fatalf("Read response got %q, want %q", string(buf[:n]), joinedRes)
		}
	}
}
