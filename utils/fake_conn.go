package utils

import (
	"bytes"
	"net"
	"time"
)

// FakeConn implements interface Conn
type FakeConn struct {
	In         *bytes.Buffer
	Out        *bytes.Buffer
	localAddr  net.Addr
	remoteAddr net.Addr
}

// NewFakeConn returns a FakeConn instance
func NewFakeConn(localAddr, remoteAddr net.Addr) *FakeConn {
	return &FakeConn{
		In:         bytes.NewBuffer(nil),
		Out:        bytes.NewBuffer(nil),
		localAddr:  localAddr,
		remoteAddr: remoteAddr,
	}
}

// NewFakeConnPair returns a FakeConn pair
func NewFakeConnPair(localAddr, remoteAddr net.Addr) (*FakeConn, *FakeConn) {
	i, o := bytes.NewBuffer(nil), bytes.NewBuffer(nil)
	return &FakeConn{
			In: i, Out: o,
			localAddr:  localAddr,
			remoteAddr: remoteAddr,
		}, &FakeConn{
			In: o, Out: i,
			localAddr:  remoteAddr,
			remoteAddr: localAddr,
		}
}

func (f *FakeConn) Read(b []byte) (int, error) {
	return f.In.Read(b)
}

func (f *FakeConn) Write(b []byte) (int, error) {
	return f.Out.Write(b)
}

func (f *FakeConn) Close() error         { return nil }
func (f *FakeConn) LocalAddr() net.Addr  { return f.localAddr }
func (f *FakeConn) RemoteAddr() net.Addr { return f.remoteAddr }

func (f *FakeConn) SetDeadline(t time.Time) error      { return nil }
func (f *FakeConn) SetReadDeadline(t time.Time) error  { return nil }
func (f *FakeConn) SetWriteDeadline(t time.Time) error { return nil }
