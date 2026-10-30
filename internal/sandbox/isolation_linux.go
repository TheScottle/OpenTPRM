//go:build linux

package sandbox

import (
	"fmt"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/unix"
)

func landlockAvailable() bool {
	// ABI probe: attr=NULL size=0 returns highest supported ABI version (man 2 landlock_create_ruleset).
	v, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, 0, 0, 0)
	if errno != 0 {
		return false
	}
	return int(v) >= 1
}

func noNewPrivsEnabled() bool {
	v, _, errno := unix.Syscall6(unix.SYS_PRCTL, uintptr(unix.PR_GET_NO_NEW_PRIVS), 0, 0, 0, 0, 0)
	return errno == 0 && v == 1
}

func setNoNewPrivs() error {
	_, _, errno := unix.Syscall6(unix.SYS_PRCTL, uintptr(unix.PR_SET_NO_NEW_PRIVS), 1, 0, 0, 0, 0)
	if errno != 0 {
		return errno
	}
	return nil
}

func seccompMode() int {
	b, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return 0
	}
	for _, line := range splitLines(string(b)) {
		if len(line) >= 9 && line[:8] == "Seccomp:" {
			var mode int
			_, _ = fmt.Sscanf(line[8:], "%d", &mode)
			return mode
		}
	}
	return 0
}

func splitLines(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		out = append(out, s[start:])
	}
	return out
}

type landlockRulesetAttr struct {
	HandledAccessFS  uint64
	HandledAccessNet uint64
}

type landlockPathBeneathAttr struct {
	AllowedAccess uint64
	ParentFD      int32
}

const landlockRulePathBeneath = 1

func tryLandlockRestrict(allowPaths []string) (bool, error) {
	if !landlockAvailable() {
		return false, nil
	}
	if len(allowPaths) == 0 {
		return false, nil
	}
	// Handled access: read file/dir only (parser child).
	handled := uint64(unix.LANDLOCK_ACCESS_FS_READ_FILE | unix.LANDLOCK_ACCESS_FS_READ_DIR | unix.LANDLOCK_ACCESS_FS_EXECUTE)
	attr := landlockRulesetAttr{HandledAccessFS: handled}
	fd, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr), 0)
	if errno != 0 {
		return false, fmt.Errorf("landlock_create_ruleset: %w", errno)
	}
	rulesetFD := int(fd)
	defer unix.Close(rulesetFD)

	for _, p := range allowPaths {
		clean := filepath.Clean(p)
		parent := clean
		fi, err := os.Stat(clean)
		if err != nil {
			// Allow missing input path parent dir if present.
			parent = filepath.Dir(clean)
		} else if !fi.IsDir() {
			parent = filepath.Dir(clean)
		}
		pfd, err := unix.Open(parent, unix.O_PATH|unix.O_CLOEXEC, 0)
		if err != nil {
			return false, fmt.Errorf("landlock open %s: %w", parent, err)
		}
		rule := landlockPathBeneathAttr{
			AllowedAccess: handled,
			ParentFD:      int32(pfd),
		}
		_, _, errno = unix.Syscall6(unix.SYS_LANDLOCK_ADD_RULE, uintptr(rulesetFD), uintptr(landlockRulePathBeneath),
			uintptr(unsafe.Pointer(&rule)), 0, 0, 0)
		_ = unix.Close(pfd)
		if errno != 0 {
			return false, fmt.Errorf("landlock_add_rule: %w", errno)
		}
	}
	if err := setNoNewPrivs(); err != nil {
		return false, err
	}
	_, _, errno = unix.Syscall(unix.SYS_LANDLOCK_RESTRICT_SELF, uintptr(rulesetFD), 0, 0)
	if errno != 0 {
		return false, fmt.Errorf("landlock_restrict_self: %w", errno)
	}
	return true, nil
}
