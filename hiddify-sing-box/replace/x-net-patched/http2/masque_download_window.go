package http2

import "sync/atomic"

// masqueDownloadPokeBytes is WINDOW_UPDATE credit bumped before/during bulk response read.
// 4 MiB covers multi-hop CF BDP better than the historical 256 KiB one-shot (peak→stock plateau).
const masqueDownloadPokeBytes = 4 << 20

// masqueDownloadRearmEveryBytes rearms an extra WINDOW_UPDATE quantum after this many body
// bytes on Extended CONNECT (CF long GET). Bootstrap-only poke was too weak once the initial
// burst drained — sustained rearm keeps peer send window ahead of stock-class stall.
const masqueDownloadRearmEveryBytes = 4 << 20

// masqueDownloadWindowLowWater: if stream recv avail falls below this after a body Read,
// force a rearm even before the byte budget (HOL / delayed WU on WAN).
const masqueDownloadWindowLowWater = 4 << 20

// masqueDownloadPokeAvailCap caps cumulative poke growth so long CF GETs cannot walk
// avail toward 2^31-1.
const masqueDownloadPokeAvailCap = 256 << 20

func (cs *clientStream) masquePokeDownloadReceiveWindowOnce() {
	if cs == nil || !cs.masqueExtendedConnect || !masqueDownloadEagerWindowEnabled() {
		return
	}
	cs.masqueDownloadPokeOnce.Do(func() {
		cs.masquePokeDownloadReceiveWindow()
	})
}

// masqueMaybeRearmDownloadReceiveWindow tops up peer send credit during long Extended CONNECT
// downloads. One-shot poke (Once) only arms the first Read — CF __down peak→plateau without
// sustained rearm matched stock-window class after the initial burst.
func (cs *clientStream) masqueMaybeRearmDownloadReceiveWindow(justRead int) {
	if cs == nil || !cs.masqueExtendedConnect || !masqueDownloadEagerWindowEnabled() || justRead <= 0 {
		return
	}
	total := atomic.AddInt64(&cs.masqueDownloadBodySeen, int64(justRead))
	prev := total - int64(justRead)

	cc := cs.cc
	cc.mu.Lock()
	avail := cs.inflow.avail
	cc.mu.Unlock()

	crossedBudget := (prev / masqueDownloadRearmEveryBytes) != (total / masqueDownloadRearmEveryBytes)
	lowWater := avail > 0 && avail < masqueDownloadWindowLowWater
	if !crossedBudget && !lowWater {
		return
	}
	cs.masquePokeDownloadReceiveWindow()
}

func masquePokeAddClamped(f *inflow, want int32) int32 {
	if want <= 0 || f.avail >= masqueDownloadPokeAvailCap {
		return 0
	}
	room := masqueDownloadPokeAvailCap - f.avail
	if want > room {
		want = room
	}
	return f.add(int(want))
}

func (cs *clientStream) masquePokeDownloadReceiveWindow() {
	cc := cs.cc
	cc.mu.Lock()
	connAdd := masquePokeAddClamped(&cc.inflow, masqueDownloadPokeBytes)
	streamAdd := masquePokeAddClamped(&cs.inflow, masqueDownloadPokeBytes)
	cc.mu.Unlock()

	if connAdd != 0 || streamAdd != 0 {
		cc.wmu.Lock()
		if connAdd != 0 {
			cc.fr.WriteWindowUpdate(0, mustUint31(connAdd))
			masqueH2NoteWindowUpdate(uint32(connAdd))
		}
		if streamAdd != 0 {
			cc.fr.WriteWindowUpdate(cs.ID, mustUint31(streamAdd))
			masqueH2NoteWindowUpdate(uint32(streamAdd))
		}
		cc.bw.Flush()
		cc.wmu.Unlock()
	}
	if masqueUploadNeedsDownloadWake(cs.reqBody) {
		masqueWakeRequestBodyWrite(cs.reqBody)
	}
	cc.mu.Lock()
	cc.cond.Broadcast()
	cc.mu.Unlock()
}
