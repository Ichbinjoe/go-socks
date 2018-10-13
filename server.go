package proxy

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
)

type CommandReply byte

const (
	SocksVersion byte = 0x05
)

const (
	Succeeded            CommandReply = 0x00
	ServerFailure        CommandReply = 0x01
	ConnForbidden        CommandReply = 0x02
	NetUnreachable       CommandReply = 0x03
	HostUnreachable      CommandReply = 0x04
	ConnRefused          CommandReply = 0x05
	TTLExpired           CommandReply = 0x06
	CommandNotSupported  CommandReply = 0x07
	AddrTypeNotSupported CommandReply = 0x08
)

type CommandType byte

const (
	Connect      CommandType = 0x01
	Bind         CommandType = 0x02
	UdpAssociate CommandType = 0x03
)

const (
	IPv4       byte = 0x01
	DomainName byte = 0x03
	IPv6       byte = 0x04
)

type AuthProvider func(*bufio.ReadWriter) error
type RulesetValidator func(CommandType, net.IP, uint16) bool

type Server struct {
	AuthProviders map[byte]AuthProvider
	Ruleset       RulesetValidator
	clients       *sync.Map
	l             *net.TCPListener
}

type client struct {
	c *net.TCPConn
	b *bufio.ReadWriter
	p *Server
}

func (s *Server) CloseClients() (e error) {
	e = nil
	s.clients.Range(func(k, v interface{}) bool {
		e = v.(*client).Close()
		return e != nil
	})
	return
}

func (c *client) Close() error {
	c.p.clients.Delete(c)

	e := c.b.Flush()
	ec := c.c.Close()
	if e == nil {
		return ec
	} else {
		return e
	}
}

func (s *Server) Close() error {
	return s.l.Close()
}

func CreateServer() *Server {
	return &Server{
		AuthProviders: make(map[byte]AuthProvider),
		Ruleset:       DenyRuleset,
		clients:       &sync.Map{},
		l:             nil,
	}
}

func (s *Server) ListenAndServe(network string, laddr *net.TCPAddr) (e error) {
	s.l, e = net.ListenTCP(network, laddr)
	if e != nil {
		return
	}

	for {
		c, e := s.l.AcceptTCP()
		if e != nil {
			return e
		}

		s.handleConnection(c)
	}
}

func (c *client) readClientHello() (ver byte, methods []byte, e error) {
	ver, e = c.b.ReadByte()
	if e != nil {
		return
	}

	nmethods, e := c.b.ReadByte()
	if e != nil {
		return
	}

	methods = make([]byte, nmethods, nmethods)
	mslice := methods[:]
	for len(mslice) > 0 {
		n, e := c.b.Read(mslice)
		if e != nil {
			return ver, methods, e
		}
		mslice = mslice[n:]
	}
	return
}

func (c *client) handleRequest() {
	responseSent := false
	defer func() {
		if r := recover(); r != nil {
			log.Printf("request handle paniced: %v\n", r)
			if !responseSent {
				writeSocksReply(c.b, ServerFailure, net.IPv4zero, 0)
			}
		}

		c.b.Flush()
	}()
	ver, err := c.b.ReadByte()
	if ver != SocksVersion || err != nil {
		panic(err)
		return
	}

	cmd, err := c.b.ReadByte()
	if err != nil {
		panic(err)
		return
	}

	_, err = c.b.ReadByte() // throw it away!
	if err != nil {
		panic(err)
		return
	}

	atyp, err := c.b.ReadByte()
	if err != nil {
		panic(err)
		return
	}

	var addr net.IP
	addrsize := 4

	switch atyp {
	// don't you just love shitty hacks like this
	case IPv6:
		addrsize = 16
		fallthrough
	case IPv4:
		addrb := make([]byte, addrsize, addrsize)
		_, err = c.b.Read(addrb)
		addr = net.IP(addrb)

		if err != nil {
			return
		}
	case DomainName:
		dlen, err := c.b.ReadByte()
		domainbuf := make([]byte, dlen, dlen)
		_, err = c.b.Read(domainbuf)

		if err != nil {
			return
		}

		ips, err := net.LookupIP(string(domainbuf))
		if err != nil {
			return
		}

		if len(ips) == 0 {
			writeSocksReply(c.b, HostUnreachable, net.IPv4zero, 0)
			responseSent = true
			return
		}

		// arbitrary as fuck
		addr = ips[0]
	default:
		writeSocksReply(c.b, AddrTypeNotSupported, net.IPv4zero, 0)
		responseSent = true
		return
	}

	addrlen := len(addr)
	if addrlen != net.IPv4len && addrlen != net.IPv6len {
		panic(fmt.Sprintf("invalid addrlen %d", addrlen))
	}

	var port uint16

	err = binary.Read(c.b, binary.BigEndian, &port)
	if err != nil {
		panic(err)
	}

	permitted := c.p.Ruleset(CommandType(cmd), addr, port)

	if !permitted {
		writeSocksReply(c.b, ConnForbidden, addr, port)
		responseSent = true
		return
	}

	switch CommandType(cmd) {
	case Connect:
		responseSent = true
		c.goConnect(addr, port)
	default:
		writeSocksReply(c.b, CommandNotSupported, addr, port)
		responseSent = true
		return
	}
}

func writeSocksReply(w io.Writer, reply CommandReply, addr net.IP, port uint16) (e error) {
	v4 := addr.To4()

	if v4 == nil {
		_, e = w.Write([]byte{SocksVersion, byte(reply), 0x00, IPv6})
		if e != nil {
			return
		}

		_, e = w.Write(addr)
	} else {
		_, e = w.Write([]byte{SocksVersion, byte(reply), 0x00, IPv4})
		if e != nil {
			return
		}

		_, e = w.Write(v4)
	}

	if e != nil {
		return
	}

	e = binary.Write(w, binary.BigEndian, &port)
	return
}

func (c *client) goConnect(ip net.IP, port uint16) {
	tcpaddr := &net.TCPAddr{
		IP:   ip,
		Port: int(port),
	}

	conn, err := net.DialTCP("tcp", nil, tcpaddr)

	if err != nil {
		writeSocksReply(c.b, ConnRefused, ip, port)
		return
	}

	defer func() {
		conn.Close()
	}()

	laddr := conn.LocalAddr().(*net.TCPAddr)

	e := writeSocksReply(c.b, Succeeded, laddr.IP, uint16(laddr.Port))
	if e != nil {
		panic(e)
	}

	e = c.b.Flush()
	if e != nil {
		panic(e)
	}

	closes := make(chan struct{})
	go func() {
		_, _ = io.Copy(conn, c.b)
		closes <- struct{}{}
	}()

	go func() {
		_, _ = io.Copy(c.b, conn)
		closes <- struct{}{}
	}()

	<-closes
	<-closes
}

func (c *client) setupConnection() (valid bool) {
	valid = false
	defer func() {
		if r := recover(); r != nil {
			valid = false
			log.Printf("authenticate encountered an ISE: %v\n", r)
		}
	}()

	// First, pull the client's 'hello' identifier / method selection message.
	ver, methods, e := c.readClientHello()
	if e != nil {
		return
	}

	if ver != 0x05 {
		return // invalid version
	}

	// auth using the first method the client wants. this should be the server's
	// choice, but this implementation will only use user/pass...
	for _, method := range methods {
		a, ok := c.p.AuthProviders[method]
		if !ok {
			continue
		}

		_, e := c.b.Write([]byte{0x05, method})
		if e != nil {
			return
		}

		e = c.b.Flush()
		if e != nil {
			return
		}

		valide := a(c.b)
		if valide == nil {
			valid = true
			return
		} else {
			break
		}
	}

	// no acceptible auth.
	// ignore errors, because we are on our way out and don't really care.
	c.b.Write([]byte{0x05, 0xff})
	c.b.Flush()
	return
}

func (c *client) start() {
	defer func() {
		c.Close()
	}()

	valid := c.setupConnection()

	if !valid {
		return
	}

	c.handleRequest()
}

func (s *Server) handleConnection(c *net.TCPConn) {
	nc := &client{
		c: c,
		b: bufio.NewReadWriter(bufio.NewReader(c), bufio.NewWriter(c)),
		p: s,
	}
	s.clients.Store(nc, struct{}{})
	go nc.start()
}
