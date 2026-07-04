package http2

// masqueDownloadPokeBytes is one-shot WINDOW_UPDATE credit before bulk response read (parity quic-go poke).
const masqueDownloadPokeBytes = 256 << 10

func (cs *clientStream) masquePokeDownloadReceiveWindowOnce() {
	if cs == nil || !cs.masqueExtendedConnect || !masqueDownloadEagerWindowEnabled() {
		return
	}
	cs.masqueDownloadPokeOnce.Do(func() {
		cs.masquePokeDownloadReceiveWindow()
	})
}

func (cs *clientStream) masquePokeDownloadReceiveWindow() {
	cc := cs.cc
	cc.mu.Lock()
	connAdd := cc.inflow.add(masqueDownloadPokeBytes)
	streamAdd := cs.inflow.add(masqueDownloadPokeBytes)
	cc.mu.Unlock()

	if connAdd != 0 || streamAdd != 0 {
		cc.wmu.Lock()
		if connAdd != 0 {
			cc.fr.WriteWindowUpdate(0, mustUint31(connAdd))
		}
		if streamAdd != 0 {
			cc.fr.WriteWindowUpdate(cs.ID, mustUint31(streamAdd))
		}
		cc.bw.Flush()
		cc.wmu.Unlock()
	}
	masqueWakeRequestBodyWrite(cs.reqBody)
	cc.mu.Lock()
	cc.cond.Broadcast()
	cc.mu.Unlock()
}
