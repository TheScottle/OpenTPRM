package questionnaire

import (
	"fmt"

	"github.com/TheScottle/OpenTPRM/internal/domain/evidence"
)

// QST-011 import limits mirror §12.5 / evidence sandbox caps.
const (
	MaxImportEntries          = evidence.MaxZIPEntries
	MaxImportUncompressed     = evidence.MaxZIPUncompressed
	MaxImportCompressionRatio = evidence.MaxZIPCompressionRatio
	MaxImportBytes            = evidence.MaxUploadBytes
	MaxImportQuestions = 5_000
	MaxImportCellRunes = 8 << 10
)

// ValidateImportArchive enforces QST-011 zip limits before any parse (no formula eval, no macros).
func ValidateImportArchive(data []byte) error {
	if len(data) > MaxImportBytes {
		return fmt.Errorf("%w: import %d bytes", evidence.ErrSizeLimit, len(data))
	}
	return evidence.ValidateArchiveLimits(data)
}
