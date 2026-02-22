package dedup

import (
	"sync"
)

// Store provides thread-safe deduplication checking
type Store struct {
	mu   sync.RWMutex
	seen map[string]struct{}
}

// NewStore initializes a new deduction store
func NewStore() *Store {
	return &Store{
		seen: make(map[string]struct{}),
	}
}

// IsDuplicate returns true if the item has already been seen.
// If not seen, it adds it to the store automatically.
func (s *Store) IsDuplicate(item string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.seen[item]; exists {
		return true
	}

	s.seen[item] = struct{}{}
	return false
}

// Exists purely checks if an item exists without adding it
func (s *Store) Exists(item string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, exists := s.seen[item]
	return exists
}

// Count returns the number of deduplicated items
func (s *Store) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.seen)
}
