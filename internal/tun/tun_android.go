//go:build android
// +build android

package tun

import "os"

var (
	onPacketFunc func([]byte)
)

//export SetOnPacketCallback
func SetOnPacketCallback(callback func([]byte)) {
	onPacketFunc = callback
}

//export WriteTUN
func WriteTUN(data []byte) {
	if onPacketFunc != nil {
		onPacketFunc(data)
	}
}

type TunDevice struct {
	name string
	fd   *os.File
}

func NewTunDevice() (*TunDevice, error) {
	return &TunDevice{
		name: "tun0",
	}, nil
}

func (t *TunDevice) SetFD(fd int) error {
	if fd < 0 {
		return os.ErrInvalid
	}
	t.fd = os.NewFile(uintptr(fd), "tun0")
	return nil
}

func (t *TunDevice) Read() ([]byte, error) {
	if t.fd == nil {
		return nil, os.ErrInvalid
	}
	buf := make([]byte, 1600)
	n, err := t.fd.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

func (t *TunDevice) Write(data []byte) error {
	if t.fd != nil {
		_, err := t.fd.Write(data)
		return err
	}
	if onPacketFunc != nil {
		onPacketFunc(data)
	}
	return nil
}

func (t *TunDevice) Close() error {
	if t.fd != nil {
		return t.fd.Close()
	}
	return nil
}

func (t *TunDevice) Name() string {
	return t.name
}

func (t *TunDevice) SetupIP(ip string) error {
	return nil
}