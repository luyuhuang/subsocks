package server

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"

	"github.com/gorilla/websocket"
	"github.com/luyuhuang/subsocks/utils"
)

func wsUpgrade(w io.Writer, path string) {
	w.Write([]byte(fmt.Sprintf("GET %s HTTP/1.1\r\n", path)))
	w.Write([]byte("Host: 127.0.0.1\r\n"))
	w.Write([]byte("Connection: Upgrade\r\n"))
	w.Write([]byte("Sec-WebSocket-Key: W4zMN8zrAeC0PuhpvvXp0A==\r\n"))
	w.Write([]byte("Sec-WebSocket-Version: 13\r\n"))
	w.Write([]byte("Upgrade: websocket\r\n"))
	w.Write([]byte("\r\n"))
}

func writeWS(w io.Writer, b []byte) {
	len := byte(len(b))
	b = append([]byte{}, b[:len]...)
	mask := []byte{1, 2, 3, 4}

	for i, c := range b {
		b[i] = c ^ mask[i%4]
	}

	w.Write([]byte{0b10000010, 0b10000000 | len})
	w.Write(mask)
	w.Write(b)
}

func closeWS(w io.Writer) {
	w.Write([]byte{0b10001000, 0b10000000, 1, 2, 3, 4})
}

func TestWSWrapperHandshake(t *testing.T) {
	cases := []struct {
		reqPath string
		serPath string
		err     error
		res     string
	}{
		{"/ws/proxy", "/ws/proxy", nil, "HTTP/1.1 101 Switching Protocols"},
		{"/ws/proxy/", "/ws/proxy", io.EOF, "HTTP/1.1 404 Not Found"},
		{"/ws/proxy", "/ws/proxy/", io.EOF, "HTTP/1.1 404 Not Found"},
		{"/ws/app", "/ws/proxy", io.EOF, "HTTP/1.1 404 Not Found"},
	}

	for _, c := range cases {
		addr, _ := net.ResolveIPAddr("tcp", "127.0.0.1:1030")
		conn := utils.NewFakeConn(addr, addr)

		wsUpgrade(conn.In, c.reqPath)

		ser := NewServer("http", "127.0.0.1:1080")
		ser.Config.WSPath = c.serPath

		ws := newWSStripper(ser, conn)
		_, err := ws.Read(nil)
		if err != c.err {
			t.Fatalf("Handshake error got %q, want %q", err, c.err)
		}

		if !strings.Contains(string(conn.Out.Bytes()), c.res) {
			t.Fatalf("Response %q dose not contains %q", string(conn.Out.Bytes()), c.res)
		}
	}
}

func TestWSWrapperData(t *testing.T) {
	cases := []struct {
		msg []byte
		res []byte
	}{
		{[]byte("send-data"), []byte("received-data")},
		{[]byte{0, 1, 2, 3, 4, 5, 6, 3, 3, 2}, []byte{34, 23, 1, 0, 34, 2, 5, 3, 32, 4}},
	}

	for _, c := range cases {
		addr, _ := net.ResolveIPAddr("tcp", "127.0.0.1:1030")
		conn := utils.NewFakeConn(addr, addr)

		wsUpgrade(conn.In, "/ws/proxy")

		ser := NewServer("http", "127.0.0.1:1080")
		ser.Config.WSPath = "/ws/proxy"

		ws := newWSStripper(ser, conn)
		_, err := ws.Read(nil)
		if err != nil {
			t.Fatalf("Handshake failed %s", err)
		}

		writeWS(conn.In, c.msg)

		buf := make([]byte, len(c.msg)*2)
		n, err := ws.Read(buf)
		if err != nil {
			t.Fatalf("Read failed: %s", err)
		}

		if !bytes.Equal(buf[:n], c.msg) {
			t.Fatalf("Read got %q, want %q", buf[:n], c.msg)
		}

		if _, err := ws.Write(c.res); err != nil {
			t.Fatalf("Write failed: %s", err)
		}

		closeWS(conn.In)
		_, err = ws.Read(buf)
		if e, ok := err.(*websocket.CloseError); !ok || e.Code != websocket.CloseNoStatusReceived {
			t.Fatalf("Read after close got %q, want CloseNoStatusReceived", err)
		}

		if !strings.Contains(string(conn.Out.Bytes()), "HTTP/1.1 101 Switching Protocols") {
			t.Fatalf("Response %q dose not contains 101 Switching Protocols", string(conn.Out.Bytes()))
		}
		if !bytes.Contains(conn.Out.Bytes(), c.res) {
			t.Fatalf("Response %q dose not contains %q", string(conn.Out.Bytes()), string(c.res))
		}
	}
}

func TestWSWrapperBuf(t *testing.T) {
	addr, _ := net.ResolveIPAddr("tcp", "127.0.0.1:1030")
	conn := utils.NewFakeConn(addr, addr)

	wsUpgrade(conn.In, "/ws/proxy")

	ser := NewServer("http", "127.0.0.1:1080")
	ser.Config.WSPath = "/ws/proxy"

	ws := newWSStripper(ser, conn)
	_, err := ws.Read(nil)
	if err != nil {
		t.Fatalf("Handshake failed %s", err)
	}

	data := "abcdefgABCDEFG"
	writeWS(conn.In, []byte(data))

	buf := make([]byte, len(data)/2)
	n, err := ws.Read(buf)
	if string(buf[:n]) != "abcdefg" {
		t.Fatalf("Read got %q, want %q", string(buf[:n]), "abcdefg")
	}

	n, err = ws.Read(buf)
	if string(buf[:n]) != "ABCDEFG" {
		t.Fatalf("Read got %q, want %q", string(buf[:n]), "ABCDEFG")
	}

	writeWS(conn.In, []byte(data))
	closeWS(conn.In)
	buf = make([]byte, len(data))
	n, err = ws.Read(buf)
	if string(buf[:n]) != data {
		t.Fatalf("Read got %q, want %q", string(buf[:n]), data)
	}

	_, err = ws.Read(buf)
	if e, ok := err.(*websocket.CloseError); !ok || e.Code != websocket.CloseNoStatusReceived {
		t.Fatalf("Read error got %q, want CloseNoStatusReceived", err)
	}
}
