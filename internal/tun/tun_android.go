//go:build android
// +build android

package tun

type TunDevice struct {
	name string
}

func NewTunDevice() (*TunDevice, error) {
	return &TunDevice{
		name: "tun0",
	}, nil
}

func (t *TunDevice) Read() ([]byte, error) {
	return nil, nil
}

func (t *TunDevice) Write(data []byte) error {
	return nil
}

func (t *TunDevice) Close() error {
	return nil
}

func (t *TunDevice) Name() string {
	return t.name
}

func (t *TunDevice) SetupIP(ip string) error {
	return nil
}