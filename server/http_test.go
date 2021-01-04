package server

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"

	"github.com/luyuhuang/subsocks/utils"
)

func TestHTTPStripper(t *testing.T) {
	cases := []struct {
		reqPath string
		serPath string
		err     error
		data    []string
		res     []string
		code    int
	}{
		{"/", "/proxy", io.EOF, []string{"socks"}, []string{""}, 404},
		{"/path", "/path/", io.EOF, []string{"socks"}, []string{""}, 404},
		{"/proxy", "/proxy", nil, []string{"socks"}, []string{"abcdefg"}, 200},
		{"/", "/", nil, []string{"socks"}, []string{"abcdefg"}, 200},
		{"/a", "/a", nil, []string{"socks", "http", "websocket"}, []string{"abcdefg", "hijk"}, 200},
	}

	for _, c := range cases {
		addr, _ := net.ResolveIPAddr("tcp", "127.0.0.1:1030")
		conn := utils.NewFakeConn(addr, addr)

		conn.In.WriteString(fmt.Sprintf("POST %s HTTP/1.1\r\n", c.reqPath))
		conn.In.WriteString("Host: 127.0.0.1\r\n")
		conn.In.WriteString("Transfer-Encoding: chunked\r\n")
		conn.In.WriteString("\r\n")
		for _, datum := range c.data {
			conn.In.WriteString(fmt.Sprintf("%X\r\n", len(datum)))
			conn.In.WriteString(datum)
			conn.In.WriteString("\r\n")
		}

		ser := NewServer("http", "127.0.0.1:1080")
		ser.Config.HTTPPath = c.serPath

		stripper := newHTTPStripper(ser, conn)

		joinedData := strings.Join(c.data, "")
		buf := make([]byte, len(joinedData)*2)
		n, err := stripper.Read(buf)
		if err != c.err {
			t.Fatalf("Read error got %q, want %q", err, c.err)
		}

		if err == nil {
			if string(buf[:n]) != joinedData {
				t.Fatalf("Read got %q, want %q", string(buf[:n]), joinedData)
			}
			for _, datum := range c.res {
				if _, err := stripper.Write([]byte(datum)); err != nil {
					t.Fatalf("Write failed: %s", err)
				}
			}
		}

		res, err := http.ReadResponse(bufio.NewReader(conn.Out), nil)
		if err != nil {
			t.Fatalf("Parse response failed: %s", err)
		}
		if res.StatusCode != c.code {
			t.Fatalf("Response code got %d, want %d", res.StatusCode, c.code)
		}

		if res.StatusCode == 200 {
			joinedRes := strings.Join(c.res, "")
			buf = make([]byte, len(joinedRes)*2)
			n, err = res.Body.Read(buf)
			if err != nil {
				t.Fatalf("Read body failed: %s", err)
			}
			if string(buf[:n]) != joinedRes {
				t.Fatalf("Read response got %q, want %q", string(buf[:n]), joinedRes)
			}
		}
	}
}

func TestHTTPAuth(t *testing.T) {
	cases := []struct {
		data               string
		username, password string
		err                error
		res                string
	}{
		{"abcde", "admin", "123456", nil, "HTTP/1.1 200 OK"},
		{"abcde", "user", "abcde", nil, "HTTP/1.1 200 OK"},
		{"", "", "", io.EOF, "HTTP/1.1 401 Unauthorized"},
		{"123456", "", "", io.EOF, "HTTP/1.1 401 Unauthorized"},
		{"abcde", "user", "abcdef", io.EOF, "HTTP/1.1 401 Unauthorized"},
		{"abcde", "luyu", "", io.EOF, "HTTP/1.1 401 Unauthorized"},
		{"abcde", "luyu", "123456", io.EOF, "HTTP/1.1 401 Unauthorized"},
		{"", "luyu", "123456", io.EOF, "HTTP/1.1 401 Unauthorized"},
	}

	for _, c := range cases {
		addr, _ := net.ResolveIPAddr("tcp", "127.0.0.1:1030")
		conn := utils.NewFakeConn(addr, addr)

		conn.In.WriteString("POST /proxy HTTP/1.1\r\n")
		conn.In.WriteString("Host: 127.0.0.1\r\n")
		conn.In.WriteString("Transfer-Encoding: chunked\r\n")
		if c.username != "" && c.password != "" {
			s := base64.StdEncoding.EncodeToString([]byte(c.username + ":" + c.password))
			conn.In.WriteString("Authorization: Basic " + s + "\r\n")
		}
		conn.In.WriteString("\r\n")
		conn.In.WriteString(fmt.Sprintf("%X\r\n", len(c.data)))
		conn.In.WriteString(c.data)
		conn.In.WriteString("\r\n")

		ser := NewServer("http", "127.0.0.1:1080")
		ser.Config.HTTPPath = "/proxy"
		ser.SetUsersFromMap(map[string]string{
			"admin": "123456",
			"user":  "abcde",
		})

		stripper := newHTTPStripper(ser, conn)
		buf := make([]byte, len(c.data)*2+1)
		n, err := stripper.Read(buf)
		if err != c.err {
			t.Fatalf("Read error got %q, want %q", err, c.err)
		}

		if err == nil {
			if string(buf[:n]) != c.data {
				t.Fatalf("Read got %q, want %q", string(buf[:n]), c.data)
			}
			if _, err := stripper.Write([]byte("-")); err != nil {
				t.Fatalf("Write failed: %s", err)
			}
		}

		if !strings.Contains(string(conn.Out.Bytes()), c.res) {
			t.Fatalf("Response %q dose not contains %q", string(conn.Out.Bytes()), c.res)
		}
	}
}
