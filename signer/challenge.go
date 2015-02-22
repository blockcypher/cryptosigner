package signer

import (
  "bytes"
  "strings"
)

const (
  SIGNATURE_CHALLENGE = iota
)

type Challenge interface {
  Check(tosign []byte) bool
  Bytes() []byte
}

func ReadChallenge(data []byte) Challenge {
  if data[0] == SIGNATURE_CHALLENGE {
    addrs := strings.Split(string(data[1:]), "|")
    return NewSignatureChallenge(addrs)
  }
  panic("Unknown challenge type.")
}

// A challenge for pre-defined payments where the output address(es) for the
// transaction are agreed upon beforehand. Will only accept data that look
// like a transaction with the proper output addresses.
type sigChallenge struct {
  addresses   []string
}

func NewSignatureChallenge(addresses []string) Challenge {
  if len(addresses) > 200 { panic("Too many addresses") }
  return &sigChallenge{addresses}
}

func (self *sigChallenge) Check(tosign []byte) bool {
  if len(tosign) < 25 { return false }

  idx := len(tosign) - 5
  for n := len(self.addresses)-1; n >= 0; n-- {
    if tosign[idx] == 172 {
      idx -= 34
      output := tosign[idx:]
      if !checkP2PKOutput(self.addresses[n], output) { return false }
    } else if tosign[idx] == 135 && tosign[idx-22] == 169 {
      idx -= 32
      output := tosign[idx:]
      if !checkP2SHOutput(self.addresses[n], output) { return false }
    } else {
      break
    }
    if n == 0 && tosign[idx] == byte(len(self.addresses)) {
      return true
    }
  }
  return false
}

func (self *sigChallenge) Bytes() []byte {
  head := []byte{SIGNATURE_CHALLENGE}
  return append(head, []byte(strings.Join(self.addresses, "|"))...)
}

func checkP2PKOutput(addr string, output []byte) bool {
  decoded := base58Decode(addr)
  checksig  := output[9] == 25 && output[10] == 118  && output[11] == 169 && output[12] == 20 &&
                output[33] == 136 && output[34] == 172
  addrmatch := bytes.Compare(output[13:33], decoded[1:21]) == 0
  return addrmatch && checksig
}

func checkP2SHOutput(addr string, output []byte) bool {
  decoded := base58Decode(addr)
  return bytes.Compare(output[12:32], decoded[1:21]) == 0
}
