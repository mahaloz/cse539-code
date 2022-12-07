package utils

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"log"
	"net"
	"net/rpc"
)

type countSocket struct {
	Conn       *tls.Conn
	bytes_sent int64
	bytes_recv int64
}

func newCountSocket(t *tls.Conn) countSocket {
	var c countSocket
	c.Conn = t
	return c
}

func (s countSocket) Read(p []byte) (int, error) {
	n, err := s.Conn.Read(p)
	s.bytes_recv += int64(n)
	//log.Printf("Read %v bytes [total %v]\n", n, s.bytes_recv)
	return n, err
}

func (s countSocket) Write(p []byte) (int, error) {
	n, err := s.Conn.Write(p)
	s.bytes_sent += int64(n)
	//log.Printf("Sent %v bytes [total %v]\n", n, s.bytes_sent)
	return n, err
}

func (s countSocket) Close() error {
	return s.Conn.Close()
}

/* For running RPC over TLS. */

func ListenAndServe(address string, keyIdx int, acceptCerts []tls.Certificate) {
	var config tls.Config
	if len(acceptCerts) > 0 {
		config.ClientAuth = tls.RequireAnyClientCert
	}
	config.InsecureSkipVerify = true
	config.Certificates = []tls.Certificate{ServerCertificates[keyIdx]}

	l, err := tls.Listen("tcp", address[len(address)-5:], &config)
	if err != nil {
		log.Fatal("Listener error:", err)
		return
	}

	defer l.Close()

	for {
		conn, err := l.Accept()
		if err != nil {
			log.Printf("Listener error:", err)
			continue
		}

		go handleOneClient(conn)
	}
}

func handleOneClient(conn net.Conn) {
	defer conn.Close()

	tlscon, ok := conn.(*tls.Conn)
	if !ok {
		log.Printf("Could not cast conn")
		return
	}

	err := tlscon.Handshake()
	if err != nil {
		log.Printf("Handshake failed:", err)
		return
	}

	//state := tlscon.ConnectionState()
	//log.Printf("Certs %v", state.PeerCertificates)

	//log.Printf("Handshake OK")

	rpc.ServeConn(newCountSocket(conn.(*tls.Conn)))
}

func DialHTTPWithTLS(network, address string,
	client_idx int, acceptCerts []tls.Certificate) (*rpc.Client, error) {
	var config tls.Config
	config.InsecureSkipVerify = true

	if client_idx >= 0 {
		config.Certificates = []tls.Certificate{ServerCertificates[client_idx]}
	}

	conn, err := tls.Dial(network, address, &config)
	if err != nil {
		log.Printf("DialHTTP error: %v", err)
		return nil, err
	}

	state := conn.ConnectionState()
	//log.Printf("State: %v", state.PeerCertificates)
	if len(acceptCerts) > 0 && !validateCert(acceptCerts, state.PeerCertificates[0]) {
		return nil, errors.New("Invalid certificate")
	}

	return rpc.NewClient(newCountSocket(conn)), nil
}

func validateCert(acceptCerts []tls.Certificate, present *x509.Certificate) bool {
	for i := 0; i < len(acceptCerts); i++ {
		if acceptCerts[i].Leaf == nil {
			certs, err := x509.ParseCertificates(acceptCerts[i].Certificate[0])
			if err != nil {
				log.Printf("Could not parse cert:", err)
				return false
			}

			acceptCerts[i].Leaf = certs[0]
		}

		if acceptCerts[i].Leaf.Equal(present) {
			return true
		}
	}
	return false
}
