package bitcoin

import (
	"bytes"
	"math/big"

	"github.com/blockcypher/cryptosigner/util"
)

// Address logic for Bitcoin family coins

// Base58Alphabet is the base 58 alphabet
const Base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

var (
	indexes  []int
	bigRadix = big.NewInt(58)
	bigZero  = big.NewInt(0)
)

// EncodeAddress encodes a bitcoin address like to string
func EncodeAddress(hash160 []byte, key byte) string {
	tosum := make([]byte, 21)
	tosum[0] = key
	copy(tosum[1:], hash160)
	cksum := util.DoubleHash(tosum)

	// Address before base58 encoding is 1 byte for netID, ripemd160 hash
	// size, plus 4 bytes of checksum (total 25).
	b := make([]byte, 25)
	b[0] = key
	copy(b[1:], hash160)
	copy(b[21:], cksum[:4])

	return base58Encode(b)
}

// VerifyChallenge verify that the transaction contains exactly the address specified
func VerifyChallenge(addresses []string, toSign []byte) bool {
	idx := len(toSign) - 5
	for n := len(addresses) - 1; n >= 0; n-- {
		if toSign[idx] == 172 {
			idx -= 34
			output := toSign[idx:]
			if !checkP2PKOutput(addresses[n], output) {
				return false
			}
		} else if toSign[idx] == 135 && toSign[idx-22] == 169 {
			idx -= 32
			output := toSign[idx:]
			if !checkP2SHOutput(addresses[n], output) {
				return false
			}
		} else {
			break
		}
		if n == 0 && toSign[idx] == byte(len(addresses)) {
			return true
		}
	}
	return false
}

// checkP2PKOutput checks whether addr is in the output
func checkP2PKOutput(addr string, output []byte) bool {
	decoded := base58Decode(addr)
	checksig := output[9] == 25 && output[10] == 118 && output[11] == 169 && output[12] == 20 &&
		output[33] == 136 && output[34] == 172
	addrmatch := bytes.Compare(output[13:33], decoded[1:21]) == 0
	return addrmatch && checksig
}

// checkP2SHOutput checks whether the addr in the output
func checkP2SHOutput(addr string, output []byte) bool {
	decoded := base58Decode(addr)
	return bytes.Compare(output[12:32], decoded[1:21]) == 0
}

func base58Decode(b string) []byte {
	if indexes == nil {
		indexes = make([]int, 128)
		for i := 0; i < len(indexes); i++ {
			indexes[i] = -1
		}
		for i := 0; i < len(Base58Alphabet); i++ {
			indexes[Base58Alphabet[i]] = i
		}
	}

	if len(b) == 0 {
		return []byte{}
	}
	input58 := make([]byte, len(b))
	for n, ch := range b {
		digit58 := -1
		if ch >= 0 && ch < 128 {
			digit58 = indexes[ch]
		}
		if digit58 < 0 {
			return []byte{}
		}

		input58[n] = byte(digit58)
	}
	zeroCount := 0
	for zeroCount < len(input58) && input58[zeroCount] == 0 {
		zeroCount++
	}

	// The encoding
	temp := make([]byte, len(b))
	j := len(temp)

	startAt := zeroCount
	for startAt < len(input58) {
		mod := divmod256(input58, startAt)
		if input58[startAt] == 0 {
			startAt++
		}

		j--
		temp[j] = mod
	}
	// Do no add extra leading zeroes, move j to first non null byte.
	for j < len(temp) && temp[j] == 0 {
		j++
	}

	return temp[j-zeroCount:]
}

func divmod256(number58 []byte, startAt int) byte {
	remainder := 0
	for i := startAt; i < len(number58); i++ {
		digit58 := int(number58[i] & 0xFF)
		temp := remainder*58 + digit58

		number58[i] = byte(temp / 256)
		remainder = temp % 256
	}

	return byte(remainder)
}

// Base58Encode encodes a byte slice to a modified base58 string.
func base58Encode(b []byte) string {
	x := new(big.Int)
	x.SetBytes(b)

	answer := make([]byte, 0)
	for x.Cmp(bigZero) > 0 {
		mod := new(big.Int)
		x.DivMod(x, bigRadix, mod)
		answer = append(answer, Base58Alphabet[mod.Int64()])
	}

	// leading zero bytes
	for _, i := range b {
		if i != 0 {
			break
		}
		answer = append(answer, Base58Alphabet[0])
	}

	// reverse
	alen := len(answer)
	for i := 0; i < alen/2; i++ {
		answer[i], answer[alen-1-i] = answer[alen-1-i], answer[i]
	}

	return string(answer)
}
