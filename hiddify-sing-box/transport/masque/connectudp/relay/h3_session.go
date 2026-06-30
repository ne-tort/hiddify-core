package relay

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	cudpasym "github.com/sagernet/sing-box/transport/masque/connectudp/asym"
)

// ErrDuplicateH3DownloadSession is returned when a second H3 download leg registers the same mux key.
var ErrDuplicateH3DownloadSession = errors.New("masque h3: duplicate asymmetric download session")

// H3SessionRegistry tracks asymmetric CONNECT-UDP sessions over HTTP/3 datagrams.
type H3SessionRegistry struct {
	mu       sync.Mutex
	sessions map[h3SessionKey]*h3AsymmetricSession
}

// DefaultH3SessionRegistry is the process-wide H3 asymmetric session registry.
var DefaultH3SessionRegistry = NewH3SessionRegistry()

// NewH3SessionRegistry builds an isolated H3 asymmetric session registry.
func NewH3SessionRegistry() *H3SessionRegistry {
	return &H3SessionRegistry{sessions: make(map[h3SessionKey]*h3AsymmetricSession)}
}

type h3SessionKey struct {
	mux    string
	target string
}

func h3SessionKeyFromHTTP(r *http.Request, target string) (h3SessionKey, error) {
	key, err := cudpasym.SessionKeyFromRequest(r, target)
	if err != nil {
		return h3SessionKey{}, err
	}
	if key.Mux == "" && key.Target == "" {
		return h3SessionKey{}, nil
	}
	return h3SessionKey{mux: key.Mux, target: key.Target}, nil
}

type h3AsymmetricSession struct {
	mu sync.Mutex

	conn       *net.UDPConn
	downlinkOK bool

	ready     chan struct{}
	readyOnce sync.Once
	refs      int
}

func (s *h3AsymmetricSession) signalReady() {
	s.readyOnce.Do(func() {
		if s.ready != nil {
			close(s.ready)
		}
	})
}

func (s *h3AsymmetricSession) waitReady(ctxDone <-chan struct{}) error {
	s.mu.Lock()
	ready := s.downlinkOK
	ch := s.ready
	s.mu.Unlock()
	if ready {
		return nil
	}
	if ch == nil {
		return errors.New("masque h3: asymmetric upload leg before download session")
	}
	select {
	case <-ch:
		return nil
	case <-ctxDone:
		return errors.New("masque h3: asymmetric session wait canceled")
	}
}

func (s *h3AsymmetricSession) sharedConn() *net.UDPConn {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.conn
}

// RegisterH3Download registers the download leg UDP socket before HTTP 200.
func (reg *H3SessionRegistry) RegisterH3Download(key h3SessionKey, conn *net.UDPConn) (*h3AsymmetricSession, error) {
	if reg == nil {
		reg = DefaultH3SessionRegistry
	}
	reg.mu.Lock()
	defer reg.mu.Unlock()
	if existing, ok := reg.sessions[key]; ok && existing != nil {
		existing.mu.Lock()
		dup := existing.downlinkOK
		existing.mu.Unlock()
		if dup {
			return nil, ErrDuplicateH3DownloadSession
		}
	}
	sess := &h3AsymmetricSession{
		conn:       conn,
		downlinkOK: true,
		ready:      make(chan struct{}),
		refs:       1,
	}
	reg.sessions[key] = sess
	sess.signalReady()
	return sess, nil
}

// AttachH3Upload waits for the download leg and bumps ref count.
func (reg *H3SessionRegistry) AttachH3Upload(key h3SessionKey) (*h3AsymmetricSession, error) {
	if reg == nil {
		reg = DefaultH3SessionRegistry
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
	return nil, fmt.Errorf("masque h3: asymmetric upload leg timed out waiting for download session target=%s", key.target)
}

// ReleaseH3 decrements refs and removes the session when zero.
func (reg *H3SessionRegistry) ReleaseH3(key h3SessionKey) {
	if reg == nil {
		reg = DefaultH3SessionRegistry
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
