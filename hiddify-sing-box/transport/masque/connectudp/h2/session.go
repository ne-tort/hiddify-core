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

// SessionRegistry tracks asymmetric CONNECT-UDP sessions.
type SessionRegistry struct {
	mu       sync.Mutex
	sessions map[sessionKey]*h2Session
}

func NewSessionRegistry() *SessionRegistry {
	return &SessionRegistry{sessions: make(map[sessionKey]*h2Session)}
}

type h2Session struct {
	mu sync.Mutex

	conn       *net.UDPConn
	downlinkW  *H2ResponseWriter
	downlinkOK bool

	ready    chan struct{}
	readyOnce sync.Once
	refs      int

	onwardMu sync.Mutex
	onward   *cudprelay.OnwardUDPWriter
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
	reg.mu.Unlock()
	if sess == nil {
		return nil, nil, false
	}
	sess.mu.Lock()
	defer sess.mu.Unlock()
	if !sess.downlinkOK {
		return nil, nil, false
	}
	return sess, sess.downlinkW, true
}

func (reg *SessionRegistry) HasActiveDownload(key sessionKey) bool {
	if reg == nil {
		reg = DefaultSessionRegistry
	}
	reg.mu.Lock()
	sess, ok := reg.sessions[key]
	reg.mu.Unlock()
	if !ok || sess == nil {
		return false
	}
	sess.mu.Lock()
	active := sess.downlinkOK
	sess.mu.Unlock()
	return active
}

func (reg *SessionRegistry) RegisterDownload(key sessionKey, conn *net.UDPConn, downlinkW *H2ResponseWriter) (*h2Session, error) {
	if reg == nil {
		reg = DefaultSessionRegistry
	}
	reg.mu.Lock()
	defer reg.mu.Unlock()
	if existing, ok := reg.sessions[key]; ok && existing != nil {
		existing.mu.Lock()
		dup := existing.downlinkOK
		existing.mu.Unlock()
		if dup {
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
	sess.signalReady()
	return sess, nil
}

func (reg *SessionRegistry) AttachUpload(key sessionKey) (*h2Session, error) {
	if reg == nil {
		reg = DefaultSessionRegistry
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		reg.mu.Lock()
		sess, ok := reg.sessions[key]
		reg.mu.Unlock()
		if ok && sess != nil {
			sess.mu.Lock()
			if sess.downlinkOK && sess.conn != nil {
				sess.refs++
				sess.mu.Unlock()
				return sess, nil
			}
			sess.mu.Unlock()
		}
		time.Sleep(time.Millisecond)
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
	conn := sess.conn
	reg.mu.Unlock()
	if refs > 0 {
		sess.mu.Unlock()
		return
	}
	reg.mu.Lock()
	delete(reg.sessions, key)
	reg.mu.Unlock()
	sess.mu.Unlock()
	if conn != nil {
		_ = conn.Close()
	}
}
