package mcp

import (
	"encoding/json"
	"sync"
	"time"

	"github.com/google/uuid"
)

// TaskStatus values for the MCP Tasks extension (AI-005).
const (
	TaskPending   = "pending"
	TaskRunning   = "running"
	TaskCompleted = "completed"
	TaskCancelled = "cancelled"
	TaskFailed    = "failed"
)

// Task is a long-running tools/call handle (AI-005 stub).
type Task struct {
	ID          string          `json:"id"`
	PrincipalID string          `json:"principal_id"`
	Tool        string          `json:"tool"`
	Status      string          `json:"status"`
	Progress    int             `json:"progress"`
	Result      json.RawMessage `json:"result,omitempty"`
	Error       string          `json:"error,omitempty"`
	CreatedAt   time.Time       `json:"created_at"`
	UpdatedAt   time.Time       `json:"updated_at"`
}

// TaskStore is an in-memory Tasks extension registry (stubs until job queue wiring).
type TaskStore struct {
	mu    sync.RWMutex
	tasks map[string]Task
}

// NewTaskStore creates an empty task registry.
func NewTaskStore() *TaskStore {
	return &TaskStore{tasks: map[string]Task{}}
}

// Create registers a new pending task owned by principalID.
func (s *TaskStore) Create(principalID, tool string) Task {
	now := time.Now().UTC()
	t := Task{
		ID: uuid.Must(uuid.NewV7()).String(), PrincipalID: principalID, Tool: tool,
		Status: TaskPending, CreatedAt: now, UpdatedAt: now,
	}
	s.mu.Lock()
	s.tasks[t.ID] = t
	s.mu.Unlock()
	return t
}

// Get returns a task only if the caller matches the creating principal (AI-005).
func (s *TaskStore) Get(id, principalID string) (Task, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	t, ok := s.tasks[id]
	if !ok || t.PrincipalID != principalID {
		return Task{}, false
	}
	return t, true
}

// UpdateProgress updates status/progress for the owning principal.
func (s *TaskStore) UpdateProgress(id, principalID, status string, progress int) (Task, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.tasks[id]
	if !ok || t.PrincipalID != principalID {
		return Task{}, false
	}
	if status != "" {
		t.Status = status
	}
	t.Progress = progress
	t.UpdatedAt = time.Now().UTC()
	s.tasks[id] = t
	return t, true
}

// Cancel marks a task cancelled for the owning principal.
func (s *TaskStore) Cancel(id, principalID string) (Task, bool) {
	return s.UpdateProgress(id, principalID, TaskCancelled, 0)
}
