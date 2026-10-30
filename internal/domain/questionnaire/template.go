package questionnaire

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
)

// TemplateVersion is immutable once published (QST-002).
type TemplateVersion struct {
	TemplateID  string            `json:"template_id"`
	Semver      string            `json:"semver"`
	Status      string            `json:"status"` // draft|published|deprecated|retired
	Content     json.RawMessage   `json:"content"`
	ContentHash string            `json:"content_hash"`
	LastEditor  string            `json:"last_editor"`
	PublishedBy string            `json:"published_by"`
	Provenance  map[string]string `json:"provenance"`
	// Optional structured questions for CEL validation at publish.
	Questions []Question `json:"questions,omitempty"`
}

// Question carries CEL expressions validated at publish (QST-003).
type Question struct {
	Key       string `json:"key"`
	VisibleIf string `json:"visible_if,omitempty"`
	Scoring   string `json:"scoring,omitempty"`
}

var (
	ErrSODViolation       = errors.New("QST-001: publisher must differ from last editor")
	ErrNotDraft           = errors.New("only draft versions can be published")
	ErrImmutablePublished = errors.New("QST-002: published versions are immutable")
)

// Publish freezes content by hash; publisher must not be last editor (QST-001/002).
func Publish(v TemplateVersion, publisher string) (TemplateVersion, error) {
	if v.Status != "draft" && v.Status != "" {
		return v, ErrNotDraft
	}
	if publisher == "" || publisher == v.LastEditor {
		return v, ErrSODViolation
	}
	if err := validateQuestionCEL(v); err != nil {
		return v, err
	}
	body := v.Content
	if len(body) == 0 && len(v.Questions) > 0 {
		encoded, err := json.Marshal(v.Questions)
		if err != nil {
			return v, err
		}
		body = encoded
		v.Content = body
	}
	sum := sha256.Sum256(body)
	v.ContentHash = hex.EncodeToString(sum[:])
	v.Status = "published"
	v.PublishedBy = publisher
	return v, nil
}

func validateQuestionCEL(v TemplateVersion) error {
	if len(v.Questions) == 0 {
		return nil
	}
	env, err := NewEnv()
	if err != nil {
		return err
	}
	for _, q := range v.Questions {
		if q.VisibleIf != "" {
			if _, err := env.Compile(q.VisibleIf); err != nil {
				return fmt.Errorf("question %s visible_if: %w", q.Key, err)
			}
		}
		if q.Scoring != "" {
			if _, err := env.Compile(q.Scoring); err != nil {
				return fmt.Errorf("question %s scoring: %w", q.Key, err)
			}
		}
	}
	return nil
}

// EnsureImmutable rejects mutation of published versions (QST-002).
func EnsureImmutable(v TemplateVersion) error {
	if v.Status != "published" {
		return nil
	}
	sum := sha256.Sum256(v.Content)
	if hex.EncodeToString(sum[:]) != v.ContentHash {
		return ErrImmutablePublished
	}
	return nil
}
