//go:build darwin

package main

/*
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <pcap.h>

// net/bpf.h cannot be included next to pcap.h: both define struct bpf_insn.
#ifndef BIOCSHDRCMPLT
#define BIOCSHDRCMPLT _IOW('B', 117, u_int)
#endif

// open_spoof_pcap opens a live capture and turns header-complete on so later
// writes keep the frame's source MAC. Returns NULL on failure.
static pcap_t *open_spoof_pcap(const char *iface, int *fd_out, char *errbuf) {
	pcap_t *p = pcap_open_live(iface, 65535, 0, 100, errbuf);
	if (p == NULL) {
		return NULL;
	}

	int fd = pcap_get_selectable_fd(p);
	if (fd < 0) {
		snprintf(errbuf, PCAP_ERRBUF_SIZE, "pcap_get_selectable_fd failed");
		pcap_close(p);
		return NULL;
	}

	unsigned int hdr_complete = 1;
	if (ioctl(fd, BIOCSHDRCMPLT, &hdr_complete) == -1) {
		snprintf(errbuf, PCAP_ERRBUF_SIZE, "BIOCSHDRCMPLT: %s", strerror(errno));
		pcap_close(p);
		return NULL;
	}

	*fd_out = fd;
	return p;
}

// write_spoof_fd writes one frame. Returns 0 on success, 1 if the driver
// rejected the source MAC (EAFNOSUPPORT), and -1 on any other failure.
static int write_spoof_fd(int fd, const unsigned char *data, int len, char *errbuf) {
	for (;;) {
		ssize_t n = write(fd, data, (size_t)len);
		if (n < 0 && errno == EINTR) {
			continue;
		}
		if (n < 0 && errno == EAFNOSUPPORT) {
			return 1;
		}
		if (n != (ssize_t)len) {
			if (n < 0) {
				snprintf(errbuf, PCAP_ERRBUF_SIZE, "bpf write: %s", strerror(errno));
			} else {
				snprintf(errbuf, PCAP_ERRBUF_SIZE, "bpf write: short write %zd", n);
			}
			return -1;
		}
		return 0;
	}
}
*/
import "C"
import (
	"fmt"
	"unsafe"
)

// darwinFrameWriter keeps one BPF device open with header-complete set.
// Without that flag, or when libpcap clears it after EAFNOSUPPORT, macOS
// replaces the Ethernet source with the interface MAC.
type darwinFrameWriter struct {
	p      *C.pcap_t
	fd     C.int
	errbuf *C.char
}

func openFrameWriter() (frameWriter, error) {
	ifname := C.CString(*iface)
	defer C.free(unsafe.Pointer(ifname))

	errbuf := (*C.char)(C.calloc(C.PCAP_ERRBUF_SIZE, 1))
	var fd C.int
	p := C.open_spoof_pcap(ifname, &fd, errbuf)
	if p == nil {
		msg := C.GoString(errbuf)
		C.free(unsafe.Pointer(errbuf))
		if msg == "" {
			msg = "pcap_open_live failed"
		}
		return nil, fmt.Errorf("%s", msg)
	}
	return &darwinFrameWriter{p: p, fd: fd, errbuf: errbuf}, nil
}

func (w *darwinFrameWriter) WriteFrame(data []byte) error {
	buf := C.CBytes(data)
	defer C.free(buf)

	rc := C.write_spoof_fd(w.fd, (*C.uchar)(buf), C.int(len(data)), w.errbuf)
	switch rc {
	case 0:
		return nil
	case 1:
		return fmt.Errorf("%w", errSpoofUnsupported)
	default:
		msg := C.GoString(w.errbuf)
		if msg == "" {
			msg = "bpf write failed"
		}
		return fmt.Errorf("%s", msg)
	}
}

func (w *darwinFrameWriter) Close() {
	if w.p != nil {
		C.pcap_close(w.p)
		w.p = nil
	}
	if w.errbuf != nil {
		C.free(unsafe.Pointer(w.errbuf))
		w.errbuf = nil
	}
}
