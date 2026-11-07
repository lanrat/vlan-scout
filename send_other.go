//go:build !darwin

package main

// openFrameWriter opens an inject handle. Linux and Windows do not rewrite
// the Ethernet source address on inject.
func openFrameWriter() (frameWriter, error) {
	return openPcapFrameWriter()
}
