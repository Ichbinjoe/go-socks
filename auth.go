package proxy

import (
	"bufio"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"net"
)

func NoAuth(_ *bufio.ReadWriter) error {
	return nil
}

var (
	InvalidCreds   error = errors.New("invalid credentials")
	InvalidVersion error = errors.New("invalid subversion")
)

func UserPass(user, pass string) AuthProvider {
	userhash := sha256.Sum256([]byte(user))
	passhash := sha256.Sum256([]byte(pass))

	return func(b *bufio.ReadWriter) (e error) {
		sver, e := b.ReadByte()
		if e != nil {
			return
		}

		if sver != 0x01 {
			return InvalidVersion
		}

		ulen, e := b.ReadByte()
		if e != nil {
			return
		}

		user_e := make([]byte, ulen, ulen)
		unamef := user_e[:]
		for e != nil && len(unamef) > 0 {
			var n int
			n, e = b.Read(unamef)
			unamef = unamef[n:]
		}

		if e != nil {
			return
		}

		plen, e := b.ReadByte()
		if e != nil {
			return
		}

		pass_e := make([]byte, plen, plen)
		passf := pass_e[:]
		for e != nil && len(passf) > 0 {
			var n int
			n, e = b.Read(passf)
			passf = passf[n:]
		}
		if e != nil {
			return
		}

		userhash_e := sha256.Sum256(user_e)
		passhash_e := sha256.Sum256(pass_e)

		ueq := subtle.ConstantTimeCompare(userhash[:], userhash_e[:])
		peq := subtle.ConstantTimeCompare(passhash[:], passhash_e[:])

		eqv := ((0x01 & ueq) << 1) | (0x01 & peq)
		if eqv&0x03 != 0x03 {
			return InvalidCreds
		} else {
			return nil
		}
	}
}

func EmptyRuleset(_ CommandType, _ net.IP, _ uint16) bool {
	return true
}

func DenyRuleset(_ CommandType, _ net.IP, _ uint16) bool {
	return false
}
