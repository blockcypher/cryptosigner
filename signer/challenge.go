package signer

import (
	"strings"

	"github.com/blockcypher/cryptosigner/signer/bitcoin"
	"github.com/blockcypher/cryptosigner/signer/ethereum"
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
func (sC *sigChallenge) Check(toSign []byte) bool {
	if len(toSign) < 25 {
		return false
	}

	switch sC.coinFamily {
	case BitcoinFamily:
		if bitcoin.VerifyChallenge(sC.addresses, toSign) {
			return true
		}
	case EthereumFamily:
		if ethereum.VerifyChallenge(sC.addresses, toSign) {
			return true
		}
	}

	return false
}

func (sC *sigChallenge) Bytes() []byte {
	head := []byte{SignatureChallenge}
	return append(head, []byte(strings.Join(sC.addresses, "|"))...)
}
