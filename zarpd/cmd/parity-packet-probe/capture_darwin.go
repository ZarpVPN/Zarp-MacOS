//go:build darwin && cgo

package main

/*
#cgo LDFLAGS: -lpcap
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <net/bpf.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

extern unsigned int bpf_filter(const struct bpf_insn *, const unsigned char *, unsigned int, unsigned int);
extern int bpf_validate(const struct bpf_insn *, int);

static int probe_filter(struct bpf_insn *f, unsigned int tcp, unsigned int udp, int ipv6) {
    if (ipv6) {
        struct bpf_insn program[] = {
            BPF_STMT(BPF_LD|BPF_W|BPF_ABS, 0),
            BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, htonl(AF_INET6), 0, 28),
            BPF_STMT(BPF_LD|BPF_W|BPF_ABS, 12),
            BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, 0, 0, 26),
            BPF_STMT(BPF_LD|BPF_W|BPF_ABS, 16),
            BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, 0, 0, 24),
            BPF_STMT(BPF_LD|BPF_W|BPF_ABS, 20),
            BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, 0, 0, 22),
            BPF_STMT(BPF_LD|BPF_W|BPF_ABS, 24),
            BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, 1, 0, 20),
            BPF_STMT(BPF_LD|BPF_W|BPF_ABS, 28),
            BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, 0, 0, 18),
            BPF_STMT(BPF_LD|BPF_W|BPF_ABS, 32),
            BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, 0, 0, 16),
            BPF_STMT(BPF_LD|BPF_W|BPF_ABS, 36),
            BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, 0, 0, 14),
            BPF_STMT(BPF_LD|BPF_W|BPF_ABS, 40),
            BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, 1, 0, 12),
            BPF_STMT(BPF_LD|BPF_B|BPF_ABS, 10),
            BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, 6, 0, 4),
            BPF_STMT(BPF_LD|BPF_H|BPF_ABS, 46),
            BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, tcp, 7, 0),
            BPF_STMT(BPF_LD|BPF_H|BPF_ABS, 44),
            BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, tcp, 5, 6),
            BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, 17, 0, 5),
            BPF_STMT(BPF_LD|BPF_H|BPF_ABS, 46),
            BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, udp, 2, 0),
            BPF_STMT(BPF_LD|BPF_H|BPF_ABS, 44),
            BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, udp, 0, 1),
            BPF_STMT(BPF_RET|BPF_K, 65535),
            BPF_STMT(BPF_RET|BPF_K, 0)
        };
        memcpy(f, program, sizeof(program));
        return sizeof(program)/sizeof(program[0]);
    }
    unsigned int family = htonl(AF_INET); // DLT_NULL family is host endian; BPF loads big endian.
    struct bpf_insn program[] = {
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS, 0),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, family, 0, 18),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS, 16),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, 0x7f000001, 0, 16),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS, 20),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, 0x7f000001, 0, 14),
        BPF_STMT(BPF_LD|BPF_B|BPF_ABS, 13),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, 6, 0, 5),
        BPF_STMT(BPF_LDX|BPF_B|BPF_MSH, 4),
        BPF_STMT(BPF_LD|BPF_H|BPF_IND, 6),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, tcp, 8, 0),
        BPF_STMT(BPF_LD|BPF_H|BPF_IND, 4),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, tcp, 6, 7),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, 17, 0, 6),
        BPF_STMT(BPF_LDX|BPF_B|BPF_MSH, 4),
        BPF_STMT(BPF_LD|BPF_H|BPF_IND, 6),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, udp, 2, 0),
        BPF_STMT(BPF_LD|BPF_H|BPF_IND, 4),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, udp, 0, 1),
        BPF_STMT(BPF_RET|BPF_K, 65535),
        BPF_STMT(BPF_RET|BPF_K, 0)
    };
    memcpy(f, program, sizeof(program));
    return sizeof(program)/sizeof(program[0]);
}

static int probe_open(unsigned int tcp, unsigned int udp, int ipv6, unsigned int *buffer) {
    int fd = -1;
    for (int i=0; i<256; i++) {
        char path[32]; snprintf(path, sizeof(path), "/dev/bpf%d", i);
        fd = open(path, O_RDONLY|O_CLOEXEC|O_NONBLOCK);
        if (fd >= 0) break;
        if (errno != EBUSY) return -errno;
    }
    if (fd < 0) return -EBUSY;
    // Install reject-all before attaching. Never read an unfiltered buffer.
    struct bpf_insn reject[] = { BPF_STMT(BPF_RET|BPF_K, 0) };
    struct bpf_program program = {1, reject};
    struct ifreq interface; memset(&interface, 0, sizeof(interface));
    memcpy(interface.ifr_name, "lo0", 4);
    // XNU lo_output/lo_start expose loopback's output tap. Input-only would
    // suppress that evidence. This affects only this private BPF descriptor.
    unsigned int size=65536, immediate=1, seesent=1, type;
    struct bpf_version version;
    struct bpf_insn filter[32];
    int count = probe_filter(filter, tcp, udp, ipv6);
    int error = 0;
    if (!bpf_validate(filter, count)) error = EINVAL;
    else if (ioctl(fd, BIOCVERSION, &version) < 0) error = errno;
    else if (version.bv_major != BPF_MAJOR_VERSION || version.bv_minor < BPF_MINOR_VERSION) error = ENOTSUP;
    else if (ioctl(fd, BIOCSETF, &program) < 0 || ioctl(fd, BIOCSBLEN, &size) < 0 ||
             ioctl(fd, BIOCSETIF, &interface) < 0 || ioctl(fd, BIOCGDLT, &type) < 0) error = errno;
    else if (type != DLT_NULL || size < 4096 || size > 0x80000) error = ENOTSUP;
    if (!error) {
        program.bf_len=count; program.bf_insns=filter;
        if (ioctl(fd, BIOCSETF, &program) < 0 || ioctl(fd, BIOCIMMEDIATE, &immediate) < 0 ||
            ioctl(fd, BIOCSSEESENT, &seesent) < 0 ||
            ioctl(fd, BIOCFLUSH, NULL) < 0 || ioctl(fd, BIOCGBLEN, &size) < 0) error = errno;
        else if (size < 4096 || size > 0x80000) error = ENOTSUP;
    }
    if (error) { close(fd); return -error; }
    *buffer = size;
    // No BIOCPROMISC, packet injection, interface flags, routes or DNS operations.
    return fd;
}

static int probe_record(const unsigned char *data, unsigned int length, unsigned int *offset, unsigned int *captured, unsigned int *next) {
    if (length < offsetof(struct bpf_hdr, bh_hdrlen)+sizeof(unsigned short)) return 0;
    struct bpf_hdr header; memset(&header, 0, sizeof(header));
    memcpy(&header, data, length < sizeof(header) ? length : sizeof(header));
    if (header.bh_hdrlen < offsetof(struct bpf_hdr, bh_hdrlen)+sizeof(unsigned short) || header.bh_hdrlen > length ||
        header.bh_caplen > length-header.bh_hdrlen || header.bh_caplen != header.bh_datalen) return 0;
    unsigned int end = header.bh_hdrlen+header.bh_caplen;
    *offset=header.bh_hdrlen; *captured=header.bh_caplen; *next=BPF_WORDALIGN(end);
    if (*next > length && end != length) return 0;
    if (end == length) *next=end;
    return 1;
}

static int probe_drops(int fd) {
    struct bpf_stat stats;
    if (ioctl(fd, BIOCGSTATS, &stats) < 0) return -errno;
    return stats.bs_drop;
}

static int probe_matches(const unsigned char *data, unsigned int length, unsigned int tcp, unsigned int udp, int ipv6) {
    struct bpf_insn filter[32];
    int count=probe_filter(filter,tcp,udp,ipv6);
    return bpf_validate(filter,count) && bpf_filter(filter,data,length,length) != 0;
}
*/
import "C"

import (
	"context"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

type wireCapture struct {
	fd       int
	cancel   context.CancelFunc
	done     chan struct{}
	packets  []wirePacket
	failure  string
	closed   bool
	stopOnce sync.Once
	drops    int
}

func openWireCapture(ctx context.Context, tcp, udp uint16, ipv6 bool) (*wireCapture, error) {
	var size C.uint
	family := C.int(0)
	if ipv6 {
		family = 1
	}
	fd := int(C.probe_open(C.uint(tcp), C.uint(udp), family, &size))
	if fd < 0 {
		return nil, syscall.Errno(-fd)
	}
	ctx, cancel := context.WithCancel(ctx)
	capture := &wireCapture{fd: fd, cancel: cancel, done: make(chan struct{})}
	go func() {
		defer close(capture.done)
		buffer := make([]byte, int(size))
		total := 0
		for ctx.Err() == nil {
			n, err := unix.Read(fd, buffer)
			if err == unix.EAGAIN || err == unix.EWOULDBLOCK || err == unix.EINTR {
				select {
				case <-ctx.Done():
					return
				case <-time.After(2 * time.Millisecond):
				}
				continue
			}
			if err != nil || n <= 0 {
				capture.failure = "capture_read_failed"
				return
			}
			total += n
			if total > 4<<20 {
				capture.failure = "capture_limit"
				return
			}
			for cursor := 0; cursor < n; {
				if len(capture.packets) >= 4096 {
					capture.failure = "capture_limit"
					return
				}
				var offset, count, next C.uint
				if C.probe_record((*C.uchar)(unsafe.Pointer(&buffer[cursor])), C.uint(n-cursor), &offset, &count, &next) == 0 || next == 0 {
					capture.failure = "capture_record_rejected"
					return
				}
				packet, ok := decodeWirePacket(buffer[cursor+int(offset) : cursor+int(offset)+int(count)])
				if !ok || packet.ipv6 != ipv6 {
					capture.failure = "capture_packet_rejected"
					return
				}
				capture.packets = append(capture.packets, packet)
				cursor += int(next)
			}
		}
	}()
	return capture, nil
}

func (c *wireCapture) stop() bool {
	c.stopOnce.Do(func() {
		c.cancel()
		<-c.done // Join reads before descriptor close/reuse.
		c.drops = int(C.probe_drops(C.int(c.fd)))
		if c.drops < 0 {
			c.failure = "capture_stats_unknown"
		} else if c.drops > 0 {
			c.failure = "capture_drops_detected"
		}
		if unix.Close(c.fd) != nil {
			c.failure = "capture_close_failed"
		} else {
			c.closed = true
		}
	})
	return c.closed
}

func (c *wireCapture) errorCode() string { return c.failure }

func nativeFilterMatches(data []byte, tcp, udp uint16) bool {
	return nativeFilterMatchesFamily(data, tcp, udp, false)
}

func nativeFilterMatchesFamily(data []byte, tcp, udp uint16, ipv6 bool) bool {
	if len(data) == 0 {
		return false
	}
	family := C.int(0)
	if ipv6 {
		family = 1
	}
	return C.probe_matches((*C.uchar)(unsafe.Pointer(&data[0])), C.uint(len(data)), C.uint(tcp), C.uint(udp), family) != 0
}
