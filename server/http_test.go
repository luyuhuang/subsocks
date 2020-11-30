package server

import (
	"fmt"
	"io"
	"net"
	"testing"

	"github.com/luyuhuang/subsocks/utils"
)

func TestHTTPStripper(t *testing.T) {
	cases := []struct {
		reqPath string
		serPath string
		err     error
		data    string
		res     string
		want    string
	}{
		{"/", "/proxy", io.EOF, "socks", "", "HTTP/1.1 404 Not Found\r\nContent-Length: 27\r\n\r\n<h1>404</h1><p>Not Found<p>"},
		{"/proxy", "/proxy", nil, "socks", "abcdefg", "HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\nabcdefg"},
		{"/path", "/path/", io.EOF, "socks", "", "HTTP/1.1 404 Not Found\r\nContent-Length: 27\r\n\r\n<h1>404</h1><p>Not Found<p>"},
		{"/", "/", nil, "socks", "abcdefg", "HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\nabcdefg"},
	}

	for _, c := range cases {
		addr, _ := net.ResolveIPAddr("tcp", "127.0.0.1:1030")
		conn := utils.NewFakeConn(addr, addr)

		conn.In.WriteString(fmt.Sprintf("POST %s HTTP/1.1\r\n", c.reqPath))
		conn.In.WriteString("Host: 127.0.0.1\r\n")
		conn.In.WriteString(fmt.Sprintf("Content-Length: %d\r\n", len(c.data)))
		conn.In.WriteString("\r\n")
		conn.In.WriteString(c.data)

		ser := NewServer("http", "127.0.0.1:1080")
		ser.Config.HTTPPath = c.serPath

		stripper := newHTTPStripper(ser, conn)

		buf := make([]byte, len(c.data)*2)
		n, err := stripper.Read(buf)
		if err != c.err {
			t.Fatalf("Read error got %q, want %q", err, c.err)
		}

		if err == nil {
			if string(buf[:n]) != c.data {
				t.Fatalf("Read got %q, want %q", string(buf[:n]), c.data)
			}
			if _, err := stripper.Write([]byte(c.res)); err != nil {
				t.Fatalf("Write failed: %s", err)
			}
		}

		if string(conn.Out.Bytes()) != c.want {
			t.Fatalf("Response got %q, want %q", string(conn.Out.Bytes()), c.want)
		}
	}
}

func TestHTTPStripperBuf(t *testing.T) {
	addr, _ := net.ResolveIPAddr("tcp", "127.0.0.1:1030")
	conn := utils.NewFakeConn(addr, addr)

	data := "abcdefgABCDEFG"

	conn.In.WriteString("POST /proxy HTTP/1.1\r\n")
	conn.In.WriteString("Host: 127.0.0.1\r\n")
	conn.In.WriteString(fmt.Sprintf("Content-Length: %d\r\n", len(data)))
	conn.In.WriteString("\r\n")
	conn.In.WriteString(data)

	ser := NewServer("http", "127.0.0.1:1080")
	ser.Config.HTTPPath = "/proxy"

	stripper := newHTTPStripper(ser, conn)
	buf := make([]byte, len(data)/2)

	n, err := stripper.Read(buf)
	if err != nil {
		t.Fatalf("Read failed: %s", err)
	}
	if string(buf[:n]) != "abcdefg" {
		t.Fatalf("Read got %q, want %q", string(buf[:n]), "abcdefg")
	}

	n, err = stripper.Read(buf)
	if err != nil {
		t.Fatalf("Read failed: %s", err)
	}
	if string(buf[:n]) != "ABCDEFG" {
		t.Fatalf("Read got %q, want %q", string(buf[:n]), "ABCDEFG")
	}

	_, err = stripper.Read(buf)
	if err != io.EOF {
		t.Fatalf("Read error got %q, want EOF", err)
	}
}
