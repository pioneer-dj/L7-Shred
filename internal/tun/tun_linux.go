//go:build linux && !android
// +build linux,!android

package tun

import (
	"os/exec"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

type TunDevice struct {
	fd   int
	name string
}

func NewTunDevice() (*TunDevice, error) {
	fd, err := syscall.Open("/dev/net/tun", syscall.O_RDWR, 0)
	if err != nil {
		return nil, err
	}

	ifr := struct {
		name  [16]byte
		flags uint16
		_     [22]byte
	}{}
	copy(ifr.name[:], "tun0")
	ifr.flags = 0x0001 | 0x1000

	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), 0x400454ca, uintptr(unsafe.Pointer(&ifr)))
	if errno != 0 {
		syscall.Close(fd)
		return nil, errno
	}

	name := strings.TrimRight(string(ifr.name[:]), "\x00")

	exec.Command("ip", "addr", "add", "10.0.0.1/24", "dev", name).Run()
	exec.Command("ip", "link", "set", "dev", name, "up").Run()

	return &TunDevice{fd: fd, name: name}, nil
}

func (t *TunDevice) ReadWithTimeout(timeout time.Duration) ([]byte, error) {
	type result struct {
		data []byte
		err  error
	}
	done := make(chan result, 1)

	go func() {
		data, err := t.Read()
		done <- result{data, err}
	}()

	select {
	case res := <-done:
		return res.data, res.err
	case <-time.After(timeout):
		return nil, nil
	}
}

func (t *TunDevice) Read() ([]byte, error) {
	buf := make([]byte, 1500)
	n, err := syscall.Read(t.fd, buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

func (t *TunDevice) Write(data []byte) error {
	_, err := syscall.Write(t.fd, data)
	return err
}

func (t *TunDevice) Close() error {
	return syscall.Close(t.fd)
}

func (t *TunDevice) Name() string {
	return t.name
}

func (t *TunDevice) SetupIP(ip string) error {
	return nil
}