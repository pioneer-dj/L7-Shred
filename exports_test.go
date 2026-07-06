package main

import (
    "io"
    "reflect"
    "testing"
)

type fakePacketSender struct {
    packets [][]byte
}

func (f *fakePacketSender) Send(data []byte) {
    f.packets = append(f.packets, append([]byte(nil), data...))
}

func TestForwardTunPacketsReadsAndForwardsPackets(t *testing.T) {
    stopChan := make(chan struct{})
    packets := [][]byte{[]byte("hello"), []byte("world")}
    idx := 0

    sender := &fakePacketSender{}
    done := make(chan struct{})

    go func() {
        forwardTunPackets(stopChan, func() ([]byte, error) {
            if idx >= len(packets) {
                return nil, io.EOF
            }
            data := packets[idx]
            idx++
            return data, nil
        }, sender, nil)
        close(done)
    }()

    <-done

    if !reflect.DeepEqual(sender.packets, packets) {
        t.Fatalf("expected %v, got %v", packets, sender.packets)
    }
}
