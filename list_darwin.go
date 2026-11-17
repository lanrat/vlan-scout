//go:build darwin

package main

/*
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>

static int if_curcap(const char *name, unsigned int *out) {
	struct ifreq ifr;
	int fd, rc;

	memset(&ifr, 0, sizeof ifr);
	strncpy(ifr.ifr_name, name, IFNAMSIZ - 1);
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		return -2;
	}
	rc = ioctl(fd, SIOCGIFCAP, &ifr);
	close(fd);
	if (rc < 0) {
		return -1;
	}
	*out = (unsigned int)ifr.ifr_curcap;
	return 0;
}
*/
import "C"
import "unsafe"

// Driver capability bits from net/if.h. Either one means the interface can
// carry an 802.1Q tag.
const (
	ifcapVLANMTU       = 0x00004
	ifcapVLANHWTagging = 0x00008
)

// interfaceCanVLAN reports whether name's driver can carry an 802.1Q tag.
// Tunnels, loopback, and Apple wireless interfaces do not advertise this.
func interfaceCanVLAN(name string) bool {
	if len(name) == 0 || len(name) >= C.IFNAMSIZ {
		return false
	}
	cname := C.CString(name)
	defer C.free(unsafe.Pointer(cname))

	var features C.uint
	switch C.if_curcap(cname, &features) {
	case 0:
		return uint32(features)&(ifcapVLANMTU|ifcapVLANHWTagging) != 0
	case -2:
		// Keep the interface listed when the check itself cannot run.
		return true
	default:
		return false
	}
}
