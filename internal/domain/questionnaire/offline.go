package questionnaire

import (
	"encoding/json"
	"errors"
	"fmt"
)

var ErrTamperedPackage = errors.New("offline package rejected: locked cell or signature mismatch")

// OfflinePackage is a signed export for vendors without portal access.
type OfflinePackage struct {
	InstanceID   string          `json:"instance_id"`
	PinnedHash   string          `json:"pinned_hash"`
	Answers      json.RawMessage `json:"answers"`
	LockedCells  []string        `json:"locked_cells"`
	ContentHash  string          `json:"content_hash"`
	SignatureOK  bool            `json:"-"`
}

// ImportOffline rejects whole-package when a locked cell was edited (AT-07).
func ImportOffline(pkg OfflinePackage, submitted map[string]any, original map[string]any) error {
	if !pkg.SignatureOK {
		return fmt.Errorf("%w: bad signature", ErrTamperedPackage)
	}
	for _, key := range pkg.LockedCells {
		o, ok1 := original[key]
		s, ok2 := submitted[key]
		if !ok1 || !ok2 || fmt.Sprint(o) != fmt.Sprint(s) {
			return fmt.Errorf("%w: locked cell %s", ErrTamperedPackage, key)
		}
	}
	return nil
}
