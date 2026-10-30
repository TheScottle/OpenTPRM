package questionnaire_test

import (
	"testing"

	"github.com/TheScottle/OpenTPRM/internal/domain/questionnaire"
)

func TestAT_07_LockedCellEditRejected(t *testing.T) {
	pkg := questionnaire.OfflinePackage{
		LockedCells: []string{"IAM-03"},
		SignatureOK: true,
	}
	err := questionnaire.ImportOffline(pkg, map[string]any{"IAM-03": "no"}, map[string]any{"IAM-03": "yes"})
	if err == nil {
		t.Fatal("AT-07: expected rejection")
	}
}
