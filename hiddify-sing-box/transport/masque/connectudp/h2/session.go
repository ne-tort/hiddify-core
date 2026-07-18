package h2

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	cudprelay "github.com/sagernet/sing-box/transport/masque/connectudp/relay"
)

// ErrDuplicateDownloadSession is returned when a second download leg registers the same mux key.
var ErrDuplicateDownloadSession = errors.New("masque h2: duplicate asymmetric download session")

var DefaultSessionRegistry = NewSessionRegistry()

const h2AttachUploadTimeout = 5 * time.Second

// SessionRegistry tracks asymmetric CONNECT-UDP sessions.
// Lock order (AUDIT B9): always reg.mu before sess.mu when both are held.
type SessionRegistry struct {
	mu       sync.Mutex
	sessions map[sessionKey]*h2Session
	// waiters: closed when RegisterDownload inserts the key (AttachUpload, no spin — B18).
	waiters map[sessionKey]chan struct{}
}

func NewSessionRegistry() *SessionRegistry {
	return &SessionRegistry{
		sessions: make(map[sessionKey]*h2Session),
		waiters:  make(map[sessionKey]chan struct{}),
	}
}

type h2Session struct {
	mu sync.Mutex

	conn       *net.UDPConn
	downlinkW  *H2ResponseWriter
	downlinkOK bool

	ready     chan struct{}
	readyOnce sync.Once
	refs      int

	onwardMu sync.Mutex
	onward   *cudprelay.OnwardUDPWriter

	// One RESULT_RELAY_STATS scope for the whole asym session (AUDIT A5 / TASKS F0.2).
	statsOnce sync.Once
	endStats  func()
}

// h2AsymRelayStatsTag is the single bench tag for asymmetric download+upload (not per-leg).
const h2AsymRelayStatsTag = "h2-asym"

func (s *h2Session) ensureRelayStats() {
	if s == nil {
		return
	}
	s.statsOnce.Do(func() {
		end := cudprelay.BeginRelaySessionStats(h2AsymRelayStatsTag)
		s.mu.Lock()
		s.endStats = end
		s.mu.Unlock()
	})
}

func (s *h2Session) finishRelayStats() {
	if s == nil {
		return
	}
	s.mu.Lock()
	end := s.endStats
	s.endStats = nil
	s.mu.Unlock()
	if end != nil {
		end()
	}
}

func (s *h2Session) signalReady() {
	s.readyOnce.Do(func() {
		if s.ready != nil {
			close(s.ready)
		}
	})
}

func (s *h2Session) waitReady(ctxDone <-chan struct{}) error {
	s.mu.Lock()
	ready := s.downlinkOK
	ch := s.ready
	s.mu.Unlock()
	if ready {
		return nil
	}
	if ch == nil {
		return errors.New("masque h2: asymmetric upload leg before download session")
	}
	select {
	case <-ch:
		return nil
	case <-ctxDone:
		return errors.New("masque h2: asymmetric session wait canceled")
	}
}

func (s *h2Session) sharedConn() *net.UDPConn {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.conn
}

func (s *h2Session) writeDownlinkICMP() error {
	s.mu.Lock()
	w := s.downlinkW
	s.mu.Unlock()
	if w == nil {
		return nil
	}
	return w.WriteUDPPayloadAsCapsules(nil)
}

func (s *h2Session) onwardWriter() cudprelay.H2UplinkOnward {
	return &sessionOnwardWriter{mu: &s.onwardMu, sess: s}
}

type sessionOnwardWriter struct {
	mu   *sync.Mutex
	sess *h2Session
}

func (o *sessionOnwardWriter) writer() *cudprelay.OnwardUDPWriter {
	if o == nil || o.sess == nil {
		return nil
	}
	o.sess.mu.Lock()
	defer o.sess.mu.Unlock()
	if o.sess.onward == nil && o.sess.conn != nil {
		o.sess.onward = cudprelay.NewOnwardUDPWriter(o.sess.conn)
	}
	return o.sess.onward
}

func (o *sessionOnwardWriter) Queue(payload []byte) (bool, error) {
	w := o.writer()
	if w == nil {
		return false, errors.New("masque h2: session onward writer unavailable")
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	return w.Queue(payload)
}

func (o *sessionOnwardWriter) Flush() (bool, error) {
	w := o.writer()
	if w == nil {
		return false, nil
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	return w.Flush()
}

func (reg *SessionRegistry) lookupDownloadSession(key sessionKey) (*h2Session, *H2ResponseWriter, bool) {
	if reg == nil {
		reg = DefaultSessionRegistry
	}
	reg.mu.Lock()
	sess := reg.sessions[key]
	if sess == nil {
		reg.mu.Unlock()
		return nil, nil, false
	}
	sess.mu.Lock()
	ok := sess.downlinkOK
	w := sess.downlinkW
	sess.mu.Unlock()
	reg.mu.Unlock()
	if !ok {
		return nil, nil, false
	}
	return sess, w, true
}

// retainSession increments refs for a looked-up download re-entry (pairs with defer Release).
func (reg *SessionRegistry) retainSession(key sessionKey) {
	if reg == nil {
		reg = DefaultSessionRegistry
	}
	reg.mu.Lock()
	sess := reg.sessions[key]
	if sess == nil {
		reg.mu.Unlock()
		return
	}
	sess.mu.Lock()
	sess.refs++
	sess.mu.Unlock()
	reg.mu.Unlock()
}

func (reg *SessionRegistry) HasActiveDownload(key sessionKey) bool {
	if reg == nil {
		reg = DefaultSessionRegistry
	}
	reg.mu.Lock()
	sess, ok := reg.sessions[key]
	if !ok || sess == nil {
		reg.mu.Unlock()
		return false
	}
	sess.mu.Lock()
	active := sess.downlinkOK
	sess.mu.Unlock()
	reg.mu.Unlock()
	return active
}

func (reg *SessionRegistry) notifyWaitersLocked(key sessionKey) {
	if ch, ok := reg.waiters[key]; ok {
		close(ch)
		delete(reg.waiters, key)
	}
}

func (reg *SessionRegistry) waiterLocked(key sessionKey) <-chan struct{} {
	if ch, ok := reg.waiters[key]; ok {
		return ch
	}
	ch := make(chan struct{})
	reg.waiters[key] = ch
	return ch
}

func (reg *SessionRegistry) RegisterDownload(key sessionKey, conn *net.UDPConn, downlinkW *H2ResponseWriter) (*h2Session, error) {
	if reg == nil {
		reg = DefaultSessionRegistry
	}
	reg.mu.Lock()
	if existing, ok := reg.sessions[key]; ok && existing != nil {
		existing.mu.Lock()
		dup := existing.downlinkOK
		existing.mu.Unlock()
		if dup {
			reg.mu.Unlock()
			return nil, ErrDuplicateDownloadSession
		}
	}
	sess := &h2Session{
		conn:       conn,
		downlinkW:  downlinkW,
		downlinkOK: true,
		ready:      make(chan struct{}),
		refs:       1,
	}
	reg.sessions[key] = sess
	reg.notifyWaitersLocked(key)
	reg.mu.Unlock()

	sess.signalReady()
	sess.ensureRelayStats()
	return sess, nil
}

func (reg *SessionRegistry) AttachUpload(key sessionKey) (*h2Session, error) {
	if reg == nil {
		reg = DefaultSessionRegistry
	}
	deadline := time.Now().Add(h2AttachUploadTimeout)
	for {
		reg.mu.Lock()
		sess := reg.sessions[key]
		if sess != nil {
			sess.mu.Lock()
			if sess.downlinkOK && sess.conn != nil {
				sess.refs++
				sess.mu.Unlock()
				reg.mu.Unlock()
				return sess, nil
			}
			sess.mu.Unlock()
			reg.mu.Unlock()
			return nil, fmt.Errorf("masque h2: asymmetric upload leg: download session not attachable target=%s", key.target)
		}
		waitCh := reg.waiterLocked(key)
		reg.mu.Unlock()
		remaining := time.Until(deadline)
		if remaining <= 0 {
			break
		}
		timer := time.NewTimer(remaining)
		select {
		case <-waitCh:
			timer.Stop()
		case <-timer.C:
		}
	}
	return nil, fmt.Errorf("masque h2: asymmetric upload leg timed out waiting for download session target=%s", key.target)
}

func (reg *SessionRegistry) Release(key sessionKey) {
	if reg == nil {
		reg = DefaultSessionRegistry
	}
	reg.mu.Lock()
	sess, ok := reg.sessions[key]
	if !ok || sess == nil {
		reg.mu.Unlock()
		return
	}
	sess.mu.Lock()
	sess.refs--
	refs := sess.refs
	var conn *net.UDPConn
	if refs <= 0 {
		conn = sess.conn
		delete(reg.sessions, key)
	}
	sess.mu.Unlock()
	reg.mu.Unlock()
	if refs > 0 {
		return
	}
	sess.finishRelayStats()
	if conn != nil {
		_ = conn.Close()
	}
}
