package ctn

import (
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"
)

// Result of SEC-CTN-006 startup self-test.
type Result struct {
	OK              bool
	Degraded        bool // Landlock unavailable is degraded, not fatal
	Failures        []string
	Warnings        []string
	UID             int
	NoNewPrivs      bool
	SeccompMode     int
	ReadOnlyRoot    bool
	LandlockOK      bool
	CapsEmpty       bool
}

// Run performs container hardening checks (SEC-CTN-006).
// In production mode, any failure except Landlock refuses start.
func Run(production bool, dataDir, secretsGlob string) Result {
	r := Result{UID: os.Getuid(), CapsEmpty: true, LandlockOK: false}
	if r.UID == 0 {
		r.Failures = append(r.Failures, "UID is 0 (must be non-root, e.g. 65532)")
	}

	// no_new_privs via prctl PR_GET_NO_NEW_PRIVS = 39
	nnp, err := getNoNewPrivs()
	if err == nil {
		r.NoNewPrivs = nnp
		if !nnp && production {
			r.Failures = append(r.Failures, "no_new_privs != 1")
		} else if !nnp {
			r.Warnings = append(r.Warnings, "no_new_privs not set (expected in container)")
		}
	}

	mode, err := getSeccompMode()
	if err == nil {
		r.SeccompMode = mode
		if mode != 2 && production {
			r.Failures = append(r.Failures, fmt.Sprintf("seccomp mode %d (want 2)", mode))
		} else if mode != 2 {
			r.Warnings = append(r.Warnings, "seccomp mode 2 not detected (expected in container)")
		}
	}

	r.ReadOnlyRoot = isReadOnly("/")
	if !r.ReadOnlyRoot && production {
		r.Failures = append(r.Failures, "root filesystem is not read-only")
	} else if !r.ReadOnlyRoot {
		r.Warnings = append(r.Warnings, "root filesystem writable (expected read-only in container)")
	}

	if dataDir != "" {
		fi, err := os.Stat(dataDir)
		if err != nil {
			if production {
				r.Failures = append(r.Failures, "data dir missing")
			}
		} else if fi.Mode().Perm()&0o077 != 0 && production {
			r.Failures = append(r.Failures, "data dir permissions too open (want 0700)")
		}
	}

	r.LandlockOK = landlockAvailable()
	if !r.LandlockOK {
		r.Degraded = true
		r.Warnings = append(r.Warnings, "Landlock unavailable (degraded sandbox isolation)")
	}

	// Capability check: on Linux read /proc/self/status CapEff
	if runtime.GOOS == "linux" {
		if eff, err := readCapEff(); err == nil && eff != "0000000000000000" {
			r.CapsEmpty = false
			if production {
				r.Failures = append(r.Failures, "effective capabilities not empty")
			} else {
				r.Warnings = append(r.Warnings, "effective capabilities not empty (expected 0 in container)")
			}
		}
	}

	r.OK = len(r.Failures) == 0
	if production && !r.OK {
		return r
	}
	// Development: treat container-only failures as warnings
	if !production {
		r.OK = true
	}
	_ = secretsGlob
	return r
}

func getNoNewPrivs() (bool, error) {
	// PR_GET_NO_NEW_PRIVS = 39
	v, _, errno := syscall.Syscall6(syscall.SYS_PRCTL, 39, 0, 0, 0, 0, 0)
	if errno != 0 {
		return false, errno
	}
	return v == 1, nil
}

func getSeccompMode() (int, error) {
	b, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "Seccomp:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				return strconv.Atoi(fields[1])
			}
		}
	}
	return 0, fmt.Errorf("seccomp not found")
}

func isReadOnly(path string) bool {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return false
	}
	// MS_RDONLY = 1
	return st.Flags&1 != 0
}

func readCapEff() (string, error) {
	b, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "CapEff:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				return fields[1], nil
			}
		}
	}
	return "", fmt.Errorf("CapEff not found")
}

func landlockAvailable() bool {
	// Best-effort: try reading landlock syscalls availability via /proc or probe.
	// Kernel >= 5.13 exposes Landlock; we treat missing as degraded.
	if runtime.GOOS != "linux" {
		return false
	}
	// Probe: if seccomp filter would allow landlock syscalls we still may lack ABI.
	// Check for landlock_create_ruleset via weak presence of documentation file.
	if _, err := os.Stat("/sys/kernel/security/landlock"); err == nil {
		return true
	}
	// Fallback: assume unavailable outside hardened hosts
	return false
}
