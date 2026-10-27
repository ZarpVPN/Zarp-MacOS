//go:build darwin && cgo

package proxy

/*
#cgo LDFLAGS: -lproc
#include <errno.h>
#include <libproc.h>
#include <signal.h>
#include <string.h>
#include <sys/proc.h>
#include <sys/proc_info.h>
#include <sys/wait.h>
#include <unistd.h>

// WNOWAIT reserves the exact child PID until Go's final Cmd.Wait. It is also
// the ownership check before every group signal, including after leader exit.
static int zarp_child_exited(int pid) {
    siginfo_t info;
    memset(&info, 0, sizeof(info));
    int result;
    do { result = waitid(P_PID, (id_t)pid, &info, WEXITED | WNOHANG | WNOWAIT); }
    while (result != 0 && errno == EINTR);
    if (result != 0)
        return -errno;
    return info.si_pid == pid;
}

static int zarp_group_live(int leader, int exited) {
    int pids[4096];
    errno = 0;
    int bytes = proc_listpids(PROC_PGRP_ONLY, (uint32_t)leader, pids, sizeof(pids));
    if (bytes < 0 || (bytes == 0 && errno != 0)) return -errno;
    if (bytes >= (int)sizeof(pids)) return -EOVERFLOW;
    int live = 0;
    for (int i = 0; i < bytes / (int)sizeof(int); i++) {
        if (pids[i] <= 0 || (pids[i] == leader && exited)) continue;
        struct proc_bsdinfo info;
        int size = proc_pidinfo(pids[i], PROC_PIDTBSDINFO, 0, &info, sizeof(info));
        if (size != sizeof(info)) {
            if (errno == ESRCH) continue;
            return -EIO;
        }
        // A listed PID can disappear/reuse between reads. Never signal it.
        if (info.pbi_pgid != leader) continue;
        if (info.pbi_status != SZOMB) live++;
    }
    return live;
}

// One final read-only scan catches descendants that changed process group but
// remain in the reserved private session. They are never individually signaled.
static int zarp_session_live_except(int leader, int except) {
    int pids[32768];
    errno = 0;
    int bytes = proc_listpids(PROC_ALL_PIDS, 0, pids, sizeof(pids));
    if (bytes <= 0) return -(errno != 0 ? errno : EIO);
    if (bytes >= (int)sizeof(pids)) return -EOVERFLOW;
    int live = 0;
    for (int i = 0; i < bytes / (int)sizeof(int); i++) {
        if (pids[i] <= 0 || pids[i] == leader || pids[i] == except) continue;
        pid_t session = getsid(pids[i]);
        if (session < 0) {
            if (errno == ESRCH) continue;
            return -EIO;
        }
        if (session != leader) continue;
        struct proc_bsdinfo info;
        int size = proc_pidinfo(pids[i], PROC_PIDTBSDINFO, 0, &info, sizeof(info));
        if (size != sizeof(info)) {
            if (errno == ESRCH) continue;
            return -EIO;
        }
        if (info.pbi_status != SZOMB) live++;
    }
    return live;
}

// A live member retains the session object. XNU PID allocation excludes both
// existing process-group IDs and session IDs. The recovery helper therefore
// pins its original SID even after the original leader dies and is reaped.
static int zarp_recovery_session(void) {
    int sid = getsid(0), pid = getpid();
    if (sid <= 1 || sid == pid || getpgrp() != pid || getppid() != sid) return -EPERM;
    return sid;
}

static int zarp_recovery_held(int sid) {
    int pid = getpid();
    return sid > 1 && getsid(0) == sid && pid != sid && getpgrp() == pid;
}

static int zarp_recovery_signal(int sid, int signal) {
    if (!zarp_recovery_held(sid)) return -EPERM;
    // Only the original session-leader group is selectable, never scanned PIDs.
    if (kill(-sid, signal) != 0 && errno != ESRCH) return -errno;
    return 0;
}
*/
import "C"

import "syscall"

func childOwnershipSupported() bool { return true }

func ownedChildExited(pid int) (bool, error) {
	result := int(C.zarp_child_exited(C.int(pid)))
	if result < 0 {
		return false, syscall.Errno(-result)
	}
	return result != 0, nil
}

func ownedGroupLive(pid int, exited bool) (int, error) {
	flag := C.int(0)
	if exited {
		flag = 1
	}
	result := int(C.zarp_group_live(C.int(pid), flag))
	if result < 0 {
		return 0, syscall.Errno(-result)
	}
	return result, nil
}

func ownedSessionLive(pid int) (int, error) {
	return ownedSessionLiveExcept(pid, 0)
}

func ownedSessionLiveExcept(pid, except int) (int, error) {
	result := int(C.zarp_session_live_except(C.int(pid), C.int(except)))
	if result < 0 {
		return 0, syscall.Errno(-result)
	}
	return result, nil
}

func recoverySession() (int, error) {
	result := int(C.zarp_recovery_session())
	if result < 0 {
		return 0, syscall.Errno(-result)
	}
	return result, nil
}

func signalRecoverySession(sid int, signal syscall.Signal) bool {
	return C.zarp_recovery_signal(C.int(sid), C.int(signal)) == 0
}

func recoverySessionHeld(sid int) bool { return C.zarp_recovery_held(C.int(sid)) != 0 }
