//go:build darwin && cgo

package traffic

/*
#cgo LDFLAGS: -lproc
#include <arpa/inet.h>
#include <errno.h>
#include <libproc.h>
#include <stdlib.h>
#include <string.h>
#include <sys/proc_info.h>
#include <sys/socket.h>
#include <time.h>

struct zarp_flow_key {
    int protocol, family;
    unsigned char local[16], remote[16];
    unsigned short local_port, remote_port;
};
struct zarp_flow_owner { int pid; char path[PROC_PIDPATHINFO_MAXSIZE]; };

static uint64_t zarp_owner_clock(void) {
    struct timespec value;
    clock_gettime(CLOCK_MONOTONIC, &value);
    return (uint64_t)value.tv_sec * 1000000000ULL + value.tv_nsec;
}

// libproc observes existing descriptors only. No process is signalled or opened.
static int zarp_owner_pid(int pid, const struct zarp_flow_key *key,
                         struct zarp_flow_owner *owner, uint64_t deadline) {
    if (zarp_owner_clock() > deadline) return -ETIMEDOUT;
    struct proc_bsdinfo before, after;
    if (proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &before, sizeof(before)) != sizeof(before)) return 0;
    int required = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, NULL, 0);
    if (required <= 0 || required > 8192 * (int)sizeof(struct proc_fdinfo)) return 0;
    int capacity = required + 32 * (int)sizeof(struct proc_fdinfo);
    struct proc_fdinfo *fds = malloc(capacity);
    if (!fds) return -ENOMEM;
    int bytes = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, fds, capacity);
    if (bytes <= 0 || bytes >= capacity) { free(fds); return 0; }
    int score = 0;
    unsigned char zero[16] = {0};
    for (int i = 0; i < bytes / (int)sizeof(struct proc_fdinfo); i++) {
        if (zarp_owner_clock() > deadline) { free(fds); return -ETIMEDOUT; }
        if (fds[i].proc_fdtype != PROX_FDTYPE_SOCKET) continue;
        struct socket_fdinfo socket;
        if (proc_pidfdinfo(pid, fds[i].proc_fd, PROC_PIDFDSOCKETINFO, &socket, sizeof(socket)) != sizeof(socket)) continue;
        struct in_sockinfo *info;
        if (key->protocol == IPPROTO_TCP && socket.psi.soi_kind == SOCKINFO_TCP) {
            if (socket.psi.soi_proto.pri_tcp.tcpsi_state < TSI_S_SYN_SENT) continue;
            info = &socket.psi.soi_proto.pri_tcp.tcpsi_ini;
        } else if (key->protocol == IPPROTO_UDP && socket.psi.soi_kind == SOCKINFO_IN && socket.psi.soi_protocol == IPPROTO_UDP) {
            info = &socket.psi.soi_proto.pri_in;
        } else continue;
        if (ntohs((uint16_t)info->insi_lport) != key->local_port) continue;
        const void *local, *remote;
        size_t length;
        if (key->family == AF_INET && (info->insi_vflag & INI_IPV4)) {
            length = 4; local = &info->insi_laddr.ina_46.i46a_addr4; remote = &info->insi_faddr.ina_46.i46a_addr4;
        } else if (key->family == AF_INET6 && (info->insi_vflag & INI_IPV6)) {
            length = 16; local = &info->insi_laddr.ina_6; remote = &info->insi_faddr.ina_6;
        } else continue;
        int local_exact = memcmp(local, key->local, length) == 0;
        int local_any = memcmp(local, zero, length) == 0;
        if (!local_exact && !(key->protocol == IPPROTO_UDP && local_any)) continue;
        int remote_exact = ntohs((uint16_t)info->insi_fport) == key->remote_port && memcmp(remote, key->remote, length) == 0;
        if (remote_exact) { score = 2; break; }
        if (key->protocol == IPPROTO_UDP && info->insi_fport == 0 && memcmp(remote, zero, length) == 0) score = 1;
    }
    free(fds);
    if (!score) return 0;
    memset(owner, 0, sizeof(*owner));
    if (proc_pidpath(pid, owner->path, sizeof(owner->path)) <= 0 || owner->path[0] != '/') return 0;
    if (proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &after, sizeof(after)) != sizeof(after) ||
        before.pbi_start_tvsec != after.pbi_start_tvsec || before.pbi_start_tvusec != after.pbi_start_tvusec) return 0;
    owner->pid = pid;
    return score;
}

static int zarp_find_owner(const struct zarp_flow_key *key, const int *recent, int recent_count,
                           struct zarp_flow_owner *owner) {
    uint64_t deadline = zarp_owner_clock() + 500000000ULL;
    for (int i = 0; i < recent_count; i++) {
        int match = zarp_owner_pid(recent[i], key, owner, deadline);
        if (match < 0) return match;
        if (match == 2) return 1;
    }
    int capacity = 32768 * (int)sizeof(int);
    int *pids = malloc(capacity);
    if (!pids) return -ENOMEM;
    int bytes = proc_listpids(PROC_ALL_PIDS, 0, pids, capacity);
    if (bytes <= 0 || bytes >= capacity) { free(pids); return -EOVERFLOW; }
    struct zarp_flow_owner candidate;
    int found = 0;
    for (int i = 0; i < bytes / (int)sizeof(int); i++) {
        if (pids[i] <= 0) continue;
        struct zarp_flow_owner current;
        int match = zarp_owner_pid(pids[i], key, &current, deadline);
        if (match < 0) { free(pids); return match; }
        if (match == 2) { *owner = current; free(pids); return 1; }
        if (match == 1) {
            if (found && candidate.pid != current.pid) { free(pids); return -EAGAIN; }
            candidate = current; found = 1;
        }
    }
    free(pids);
    if (found) { *owner = candidate; return 1; }
    return 0;
}
*/
import "C"

import (
	"context"
	"errors"
	"sync"
	"unsafe"

	"github.com/feg55/zarp-macos/zarpd/tunproxy"
)

func NativeOwnerSupported() bool { return true }

type NativeOwners struct {
	mu     sync.Mutex
	recent []C.int
}

func (r *NativeOwners) Owner(ctx context.Context, flow tunproxy.Flow) (Owner, error) {
	unknown := errors.New("application ownership is unavailable")
	if !flow.Source.IsValid() || !flow.Destination.IsValid() || flow.Source.Addr().Is4() != flow.Destination.Addr().Is4() || flow.Network != "tcp" && flow.Network != "udp" {
		return Owner{}, unknown
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return Owner{}, err
	}
	var key C.struct_zarp_flow_key
	key.protocol = C.IPPROTO_TCP
	if flow.Network == "udp" {
		key.protocol = C.IPPROTO_UDP
	}
	key.family = C.AF_INET6
	if flow.Source.Addr().Is4() {
		key.family = C.AF_INET
	}
	local, remote := flow.Source.Addr().AsSlice(), flow.Destination.Addr().AsSlice()
	C.memcpy(unsafe.Pointer(&key.local[0]), unsafe.Pointer(&local[0]), C.size_t(len(local)))
	C.memcpy(unsafe.Pointer(&key.remote[0]), unsafe.Pointer(&remote[0]), C.size_t(len(remote)))
	key.local_port, key.remote_port = C.ushort(flow.Source.Port()), C.ushort(flow.Destination.Port())
	var hint *C.int
	if len(r.recent) > 0 {
		hint = &r.recent[0]
	}
	var value C.struct_zarp_flow_owner
	if C.zarp_find_owner(&key, hint, C.int(len(r.recent)), &value) != 1 {
		return Owner{}, unknown
	}
	if err := ctx.Err(); err != nil {
		return Owner{}, err
	}
	kept := []C.int{value.pid}
	for _, pid := range r.recent {
		if pid != value.pid && len(kept) < 64 {
			kept = append(kept, pid)
		}
	}
	r.recent = kept
	return Owner{PID: int(value.pid), Executable: C.GoString(&value.path[0])}, nil
}
