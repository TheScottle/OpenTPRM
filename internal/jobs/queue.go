package jobs

import (
	"sync"
	"time"
)

// Job is a persistent queue entry (M4+).
type Job struct {
	ID        string
	Type      string
	PayloadRef string
	State     string
	Attempts  int
	RunAfter  time.Time
	LeaseUntil time.Time
	Error     string
}

// MemoryQueue is a process-local queue used until SQLite-backed workers are wired.
type MemoryQueue struct {
	mu   sync.Mutex
	jobs []Job
}

func NewMemoryQueue() *MemoryQueue { return &MemoryQueue{} }

func (q *MemoryQueue) Enqueue(j Job) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if j.State == "" {
		j.State = "pending"
	}
	q.jobs = append(q.jobs, j)
}

func (q *MemoryQueue) Len() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.jobs)
}
