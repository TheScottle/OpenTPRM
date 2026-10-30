//go:build !linux

package sandbox

func landlockAvailable() bool { return false }

func noNewPrivsEnabled() bool { return false }

func setNoNewPrivs() error { return nil }

func seccompMode() int { return 0 }

func tryLandlockRestrict(allowPaths []string) (bool, error) {
	_ = allowPaths
	return false, nil
}
