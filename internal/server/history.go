package server

import (
	"sync"
	"time"
)

// HistoryEntry records one probe outcome for the debug UI.
type HistoryEntry struct {
	ID        int64
	Module    string
	Target    string
	Success   bool
	Timestamp time.Time
}

// History is a bounded FIFO of probe outcomes.
type History struct {
	mu       sync.Mutex
	nextID   int64
	maxItems int
	items    []HistoryEntry
}

// NewHistory returns a bounded FIFO of the last maxItems probe outcomes.
// 100 entries × ~100B metadata each ≈ ~10KB worst-case retention (Output field removed).
func NewHistory(maxItems int) *History {
	if maxItems <= 0 {
		maxItems = 100
	}
	return &History{maxItems: maxItems}
}

// Add records a probe outcome.
func (h *History) Add(moduleName, target string, success bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.nextID++
	e := HistoryEntry{ID: h.nextID, Module: moduleName, Target: target, Success: success, Timestamp: time.Now()}
	h.items = append(h.items, e)
	if len(h.items) > h.maxItems {
		h.items = h.items[len(h.items)-h.maxItems:]
	}
}

// List returns a snapshot of the current history, oldest first.
func (h *History) List() []HistoryEntry {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]HistoryEntry, len(h.items))
	copy(out, h.items)
	return out
}
