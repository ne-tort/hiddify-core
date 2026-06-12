package server

import "sync/atomic"

// StartErrorStore holds the last Serve/listen error from background MASQUE server goroutines.
type StartErrorStore struct {
	v atomic.Value
}

type startErrorState struct {
	err error
}

// Clear resets the stored error (fresh listen/Serve cycle).
func (s *StartErrorStore) Clear() {
	if s == nil {
		return
	}
	s.v.Store(startErrorState{})
}

// Store records a Serve failure.
func (s *StartErrorStore) Store(err error) {
	if s == nil {
		return
	}
	s.v.Store(startErrorState{err: err})
}

// Load returns the last stored error, or nil.
func (s *StartErrorStore) Load() error {
	if s == nil {
		return nil
	}
	value := s.v.Load()
	if value == nil {
		return nil
	}
	state, ok := value.(startErrorState)
	if !ok {
		return nil
	}
	return state.err
}
