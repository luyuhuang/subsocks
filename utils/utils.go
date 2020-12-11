package utils

import (
	"crypto/subtle"
	"io"
	"sync"
)

// buffer pools
var (
	SPool = sync.Pool{
		New: func() interface{} {
			return make([]byte, 576)
		},
	} // small buff pool
	LPool = sync.Pool{
		New: func() interface{} {
			return make([]byte, 64*1024+262)
		},
	} // large buff pool for udp
)

// Transport rw1 and rw2
func Transport(rw1, rw2 io.ReadWriter) error {
	errc := make(chan error, 1)
	go func() {
		_, err := io.Copy(rw1, rw2)
		errc <- err
	}()

	go func() {
		_, err := io.Copy(rw2, rw1)
		errc <- err
	}()

	if err := <-errc; err != nil && err == io.EOF {
		return err
	}
	return nil
}

// StrEQ returns whether s1 and s2 are equal
func StrEQ(s1, s2 string) bool {
	return subtle.ConstantTimeCompare([]byte(s1), []byte(s2)) == 1
}
