package signer

import (
	"strings"

	"github.com/blockcypher/cryptosigner/signer/bitcoin"
)

const (
	// SignatureChallenge byte iota
	SignatureChallenge = iota
)

// Challenge interface
type Challenge interface {
	Check(tosign []byte) bool
	Bytes() []byte
}

// ReadChallenge reads a challenge from bytes
func ReadChallenge(data []byte, coinFamily CoinFamily) Challenge {
	if data[0] == SignatureChallenge {
		addrs := strings.Split(string(data[1:]), "|")
		return NewSignatureChallenge(addrs, coinFamily)
	}
	panic("Unknown challenge type.")
}

// A challenge for pre-defined payments where the output address(es) for the
// transaction are agreed upon beforehand. Will only accept data that look
// like a transaction with the proper output addresses.
type sigChallenge struct {
	addresses  []string
	coinFamily CoinFamily
}

// NewSignatureChallenge creates a new signature challenge from a slice of addresses
func NewSignatureChallenge(addresses []string, coinFamily CoinFamily) Challenge {
	if len(addresses) > 200 {
		panic("Too many addresses")
	}
	return &sigChallenge{addresses, coinFamily}
}

// Check verify a signature challenge
func (sC *sigChallenge) Check(tosign []byte) bool {
	if len(tosign) < 25 {
		return false
	}

	idx := len(tosign) - 5
	for n := len(sC.addresses) - 1; n >= 0; n-- {
		if tosign[idx] == 172 {
			idx -= 34
			output := tosign[idx:]
			if !bitcoin.CheckP2PKOutput(sC.addresses[n], output) {
				return false
			}
		} else if tosign[idx] == 135 && tosign[idx-22] == 169 {
			idx -= 32
			output := tosign[idx:]
			if !bitcoin.CheckP2SHOutput(sC.addresses[n], output) {
				return false
			}
		} else {
			break
		}
		if n == 0 && tosign[idx] == byte(len(sC.addresses)) {
			return true
		}
	}
	return false
}

func (sC *sigChallenge) Bytes() []byte {
	head := []byte{SignatureChallenge}
	return append(head, []byte(strings.Join(sC.addresses, "|"))...)
}
