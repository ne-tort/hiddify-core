package masque

import (
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/sagernet/sing-box/transport/masque/h3"
)

var errBenchDuration = errors.New("masque: bench duration elapsed")

type benchWriteToSink struct {
	deadline time.Time
	total    int64
}

func (s *benchWriteToSink) Write(p []byte) (int, error) {
	if time.Now().After(s.deadline) {
		return 0, errBenchDuration
	}
	s.total += int64(len(p))
	return len(p), nil
}

func measureTCPDownloadMbps(conn net.Conn, duration time.Duration) (int64, float64, error) {
	deadline := time.Now().Add(duration)
	buf := make([]byte, 256*1024)
	var total int64
	for time.Now().Before(deadline) {
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, err := conn.Read(buf)
		if n > 0 {
			total += int64(n)
		}
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() && total > 0 {
				break
			}
			if err == io.EOF {
				break
			}
			if total > 0 {
				break
			}
			return 0, 0, err
		}
	}
	secs := duration.Seconds()
	if secs <= 0 {
		secs = 1
	}
	return total, float64(total*8) / secs / 1e6, nil
}

func measureTCPDownloadCopyMbps(conn net.Conn, duration time.Duration) (int64, float64, error) {
	deadline := time.Now().Add(duration)
	_ = conn.SetReadDeadline(deadline)
	defer conn.SetReadDeadline(time.Time{})
	sink := &benchWriteToSink{deadline: deadline}
	_, err := io.Copy(sink, conn)
	if err != nil && err != errBenchDuration && err != io.EOF {
		if sink.total == 0 {
			return 0, 0, err
		}
	}
	secs := duration.Seconds()
	if secs <= 0 {
		secs = 1
	}
	return sink.total, float64(sink.total*8) / secs / 1e6, nil
}

func measureTCPDownloadWriteToMbps(conn net.Conn, duration time.Duration) (int64, float64, error) {
	wt, ok := conn.(io.WriterTo)
	if !ok {
		return 0, 0, fmt.Errorf("masque: conn lacks io.WriterTo (prod download path)")
	}
	deadline := time.Now().Add(duration)
	_ = conn.SetReadDeadline(deadline)
	defer conn.SetReadDeadline(time.Time{})
	sink := &benchWriteToSink{deadline: deadline}
	_, err := wt.WriteTo(sink)
	if err != nil && err != errBenchDuration && err != io.EOF {
		if sink.total == 0 {
			return 0, 0, err
		}
	}
	secs := duration.Seconds()
	if secs <= 0 {
		secs = 1
	}
	return sink.total, float64(sink.total*8) / secs / 1e6, nil
}

func measureTCPUploadMbps(conn net.Conn, duration time.Duration) (int64, float64, error) {
	deadline := time.Now().Add(duration)
	buf := make([]byte, 256*1024)
	var total int64
	for time.Now().Before(deadline) {
		_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
		n, err := conn.Write(buf)
		if n > 0 {
			total += int64(n)
		}
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() && total > 0 {
				break
			}
			if err == io.EOF {
				break
			}
			if total > 0 {
				break
			}
			return 0, 0, err
		}
	}
	secs := duration.Seconds()
	if secs <= 0 {
		secs = 1
	}
	mbps := float64(total*8) / secs / 1e6
	return total, mbps, nil
}

func measureTCPUploadMbpsWriteSize(conn net.Conn, duration time.Duration, writeSize int) (int64, float64, error) {
	if writeSize <= 0 {
		writeSize = 1
	}
	deadline := time.Now().Add(duration)
	buf := make([]byte, writeSize)
	var total int64
	for time.Now().Before(deadline) {
		_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
		n, err := conn.Write(buf)
		if n > 0 {
			total += int64(n)
		}
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() && total > 0 {
				break
			}
			if err == io.EOF {
				break
			}
			if total > 0 {
				break
			}
			return 0, 0, err
		}
	}
	secs := duration.Seconds()
	if secs <= 0 {
		secs = 1
	}
	return total, float64(total*8) / secs / 1e6, nil
}

// measureSegmentDuplexMbps runs concurrent WriteTo download + bulk upload on one bidi conn.
func measureSegmentDuplexMbps(conn net.Conn, duration time.Duration) (down, up, minLeg float64, err error) {
	type downRes struct {
		mbps float64
		err  error
	}
	type upRes struct {
		bytes int64
	}
	downDone := make(chan downRes, 1)
	upDone := make(chan upRes, 1)
	start := make(chan struct{})
	downloadArmed := make(chan struct{}, 1)
	prevArmedHook := h3.TestDuplexDownloadArmedHook
	h3.TestDuplexDownloadArmedHook = downloadArmed
	defer func() { h3.TestDuplexDownloadArmedHook = prevArmedHook }()
	go func() {
		<-start
		n, mbps, e := measureTCPDownloadWriteToMbps(conn, duration)
		if e != nil && n == 0 {
			downDone <- downRes{err: e}
			return
		}
		downDone <- downRes{mbps: mbps}
	}()
	go func() {
		<-start
		<-downloadArmed
		chunk := make([]byte, 256*1024)
		var upTotal int64
		stop := time.Now().Add(duration)
		for time.Now().Before(stop) {
			n, e := conn.Write(chunk)
			if n > 0 {
				upTotal += int64(n)
			}
			if e != nil {
				break
			}
		}
		upDone <- upRes{bytes: upTotal}
	}()
	close(start)

	dr := <-downDone
	if dr.err != nil {
		return 0, 0, 0, dr.err
	}
	ur := <-upDone
	secs := duration.Seconds()
	if secs <= 0 {
		secs = 1
	}
	up = float64(ur.bytes*8) / secs / 1e6
	down = dr.mbps
	minLeg = down
	if up < minLeg {
		minLeg = up
	}
	return down, up, minLeg, nil
}
