//go:build windows
// +build windows

package tun

import (
	"log"
	"os/exec"
	"syscall"

	"golang.zx2c4.com/wireguard/tun"
)

const tunOffset = 4

type TunDevice struct {
	device tun.Device
	name   string
}

func NewTunDevice() (*TunDevice, error) {
	oldAdapter := exec.Command("wintun", "delete", "l7shred")
	oldAdapter.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	oldAdapter.Run()

	tunDev, err := tun.CreateTUN("l7shred", 1400)
	if err != nil {
		return nil, err
	}
	name, err := tunDev.Name()
	if err != nil {
		return nil, err
	}
	log.Printf("TUN device created: %s", name)

	cmd := exec.Command("netsh", "interface", "ipv4", "set", "subinterface",
		name, "mtu=1350", "store=active")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	cmd.Run()

	return &TunDevice{device: tunDev, name: name}, nil
}

func (t *TunDevice) Read() ([]byte, error) {
	buf := make([]byte, 1500+tunOffset)
	bufs := make([][]byte, 1)
	bufs[0] = buf
	sizes := make([]int, 1)
	n, err := t.device.Read(bufs, sizes, tunOffset)
	if err != nil {
		return nil, err
	}
	if n == 0 {
		return nil, nil
	}
	return bufs[0][tunOffset : tunOffset+sizes[0]], nil
}

func (t *TunDevice) Write(data []byte) error {
	buf := make([]byte, tunOffset+len(data))
	copy(buf[tunOffset:], data)
	bufs := make([][]byte, 1)
	bufs[0] = buf
	_, err := t.device.Write(bufs, tunOffset)
	return err
}

func (t *TunDevice) Close() error {
	return t.device.Close()
}

func (t *TunDevice) SetupIP(ip string) error {
	delCmd := exec.Command("netsh", "interface", "ip", "delete", "address",
		t.name, ip)
	delCmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	delCmd.Run()

	cmd := exec.Command("netsh", "interface", "ip", "set", "address",
		t.name, "static", ip, "255.255.255.0", "gateway=none")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	if err := cmd.Run(); err != nil {
		log.Printf("[TUN] netsh set address error: %v, trying alternative method", err)
		cmd = exec.Command("netsh", "interface", "ip", "set", "address",
			"name="+t.name, "source=static", "addr="+ip, "mask=255.255.255.0")
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		if err := cmd.Run(); err != nil {
			log.Printf("[TUN] netsh alternative also failed: %v", err)
			return err
		}
	}
	log.Printf("Set IP %s on interface %s", ip, t.name)
	return nil
}

func (t *TunDevice) Name() string {
	return t.name
}

func (t *TunDevice) SetFD(fd int) error {
	return nil
}