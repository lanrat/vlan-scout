package main

import (
	"errors"
	"fmt"
	"log"
	"sync"

	"github.com/google/gopacket/pcap"
)

// errSpoofUnsupported is returned when the OS refuses to transmit a frame
// whose source MAC is not the interface address.
var errSpoofUnsupported = errors.New("interface rejected spoofed source MAC")

var spoofWarn sync.Once

// frameWriter injects Ethernet frames on one already-open handle.
type frameWriter interface {
	WriteFrame(data []byte) error
	Close()
}

var (
	injectMu     sync.Mutex
	injectWriter frameWriter
)

// startInject opens one inject handle for the whole scan. Probes from every
// worker share it instead of opening a new BPF device per frame.
func startInject() error {
	injectMu.Lock()
	defer injectMu.Unlock()
	if injectWriter != nil {
		return nil
	}
	w, err := openFrameWriter()
	if err != nil {
		return err
	}
	injectWriter = w
	return nil
}

// stopInject closes the shared inject handle.
func stopInject() {
	injectMu.Lock()
	defer injectMu.Unlock()
	if injectWriter != nil {
		injectWriter.Close()
		injectWriter = nil
	}
}

// writeFrame injects one Ethernet frame on the selected interface.
// On macOS the frame is written with the BPF header-complete flag set so the
// kernel keeps the source MAC. If the driver rejects that, it falls back to
// libpcap, which may substitute the interface MAC.
func writeFrame(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty frame")
	}
	injectMu.Lock()
	defer injectMu.Unlock()

	if injectWriter == nil {
		w, err := openFrameWriter()
		if err != nil {
			return err
		}
		defer w.Close()
		return writeOn(w, data, false)
	}
	return writeOn(injectWriter, data, true)
}

// writeOn sends data through w. keep controls whether a spoof rejection
// replaces the process-wide inject handle.
func writeOn(w frameWriter, data []byte, keep bool) error {
	err := w.WriteFrame(data)
	if err == nil || !errors.Is(err, errSpoofUnsupported) {
		return err
	}
	spoofWarn.Do(func() {
		log.Printf("interface rejected source MAC %s (%v); resending without preserving it", *macAddress, err)
	})
	fallback, ferr := openPcapFrameWriter()
	if ferr != nil {
		return ferr
	}
	if keep {
		w.Close()
		injectWriter = fallback
		return fallback.WriteFrame(data)
	}
	defer fallback.Close()
	return fallback.WriteFrame(data)
}

type pcapFrameWriter struct {
	handle *pcap.Handle
}

func openPcapFrameWriter() (frameWriter, error) {
	// A negative timeout leaves the handle blocking. A positive timeout makes
	// gopacket set the fd nonblocking, and a later write can return EAGAIN.
	handle, err := pcap.OpenLive(*iface, 65535, false, pcap.BlockForever)
	if err != nil {
		return nil, err
	}
	return &pcapFrameWriter{handle: handle}, nil
}

func (w *pcapFrameWriter) WriteFrame(data []byte) error {
	return w.handle.WritePacketData(data)
}

func (w *pcapFrameWriter) Close() {
	if w.handle != nil {
		w.handle.Close()
		w.handle = nil
	}
}
