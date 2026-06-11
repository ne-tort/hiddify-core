package masquethin

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
)

// ServeSOCKS5 listens on addr and forwards TCP via MASQUE CONNECT authority (cfg).
func ServeSOCKS5(ctx context.Context, addr string, cfg ClientConfig) error {
	client, err := NewClient(cfg)
	if err != nil {
		return err
	}
	defer client.Close()
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	defer ln.Close()
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	for {
		tcp, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		go handleSOCKS5Conn(ctx, tcp, client)
	}
}

func handleSOCKS5Conn(ctx context.Context, conn net.Conn, client *Client) {
	defer conn.Close()
	targetHost, targetPort, err := socks5Handshake(conn)
	if err != nil {
		return
	}
	remote, err := client.DialTCP(ctx, targetHost, targetPort)
	if err != nil {
		return
	}
	defer remote.Close()
	errCh := make(chan error, 2)
	go func() { _, err := io.Copy(remote, conn); errCh <- err }()
	go func() { _, err := io.Copy(conn, remote); errCh <- err }()
	<-errCh
}

func socks5Handshake(conn net.Conn) (host string, port uint16, err error) {
	buf := make([]byte, 258)
	if _, err = io.ReadFull(conn, buf[:2]); err != nil {
		return "", 0, err
	}
	if buf[0] != 0x05 {
		return "", 0, fmt.Errorf("socks: bad version")
	}
	nMethods := int(buf[1])
	if _, err = io.ReadFull(conn, buf[:nMethods]); err != nil {
		return "", 0, err
	}
	if _, err = conn.Write([]byte{0x05, 0x00}); err != nil {
		return "", 0, err
	}
	if _, err = io.ReadFull(conn, buf[:4]); err != nil {
		return "", 0, err
	}
	if buf[0] != 0x05 || buf[1] != 0x01 {
		_, _ = conn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return "", 0, fmt.Errorf("socks: only CONNECT")
	}
	atyp := buf[3]
	switch atyp {
	case 0x01:
		if _, err = io.ReadFull(conn, buf[:6]); err != nil {
			return "", 0, err
		}
		host = net.IP(buf[:4]).String()
		port = binary.BigEndian.Uint16(buf[4:6])
	case 0x03:
		if _, err = io.ReadFull(conn, buf[:1]); err != nil {
			return "", 0, err
		}
		domainLen := int(buf[0])
		if _, err = io.ReadFull(conn, buf[:domainLen+2]); err != nil {
			return "", 0, err
		}
		host = string(buf[:domainLen])
		port = binary.BigEndian.Uint16(buf[domainLen : domainLen+2])
	case 0x04:
		if _, err = io.ReadFull(conn, buf[:18]); err != nil {
			return "", 0, err
		}
		host = net.IP(buf[:16]).String()
		port = binary.BigEndian.Uint16(buf[16:18])
	default:
		return "", 0, fmt.Errorf("socks: bad atyp %d", atyp)
	}
	if _, err = conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		return "", 0, err
	}
	_ = strconv.Itoa(int(port))
	return host, port, nil
}
