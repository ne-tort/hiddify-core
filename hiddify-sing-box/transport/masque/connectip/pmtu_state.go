package connectip

import (
	"sync"
	"sync/atomic"
)

// UDPPMTUState tracks the effective UDP payload ceiling for the CONNECT-IP UDP bridge.
type UDPPMTUState struct {
	Mu                   sync.Mutex
	CurrentPayload       atomic.Int64
	MinPayload           atomic.Int64
	MaxPayload           atomic.Int64
	SuccessSinceDecrease atomic.Int64
	LastMinus64UnixMilli atomic.Int64
}

// NewUDPPMTUState constructs PMTU state with the given payload bounds.
func NewUDPPMTUState(currentPayload, minPayload, maxPayload int) *UDPPMTUState {
	s := &UDPPMTUState{}
	s.CurrentPayload.Store(int64(currentPayload))
	s.MinPayload.Store(int64(minPayload))
	s.MaxPayload.Store(int64(maxPayload))
	return s
}
