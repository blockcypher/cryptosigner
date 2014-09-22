package signer

import (
  "bytes"
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
    return NewSignatureChallenge(string(data[1:]))
  }
  panic("Unknown challenge type.")
}

type sigChallenge struct {
  address string
}

func NewSignatureChallenge(address string) Challenge {
  return &sigChallenge{address}
}

func (self *sigChallenge) Check(tosign []byte) bool {
  if len(tosign) < 25 { return false }
  decoded := base58Decode(self.address)
  // 4 last bytes of tx are the lock time, byte before is OP_CHECKSIG, address is right before that
  // before are the address length, OP_DUP OP_HAS160 and the length of the script
  output := tosign[len(tosign)-39:]
  oneoutput := output[0] == 1
  checksig  := output[9] == 25 && output[10] == 118  && output[11] == 169 && output[12] == 20 &&
                output[33] == 136 && output[34] == 172
  addrmatch := bytes.Compare(output[13:33], decoded[1:21]) == 0
  return oneoutput && addrmatch && checksig
}

func (self *sigChallenge) Bytes() []byte {
  head := []byte{SIGNATURE_CHALLENGE}
  return append(head, []byte(self.address)...)
}
