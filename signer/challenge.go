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
  output := tosign[len(tosign)-34:]
  oneoutput := bytes.Compare([]byte{1, 0, 0, 0}, output[0:4]) == 0
  checksig  := output[4] == 25 && output[5] == 118  && output[6] == 169 && output[7] == 20 &&
                output[28] == 136 && output[29] == 172
  addrmatch := bytes.Compare(output[8:28], decoded[1:21]) == 0
  return oneoutput && addrmatch && checksig
}

func (self *sigChallenge) Bytes() []byte {
  head := []byte{SIGNATURE_CHALLENGE}
  return append(head, []byte(self.address)...)
}
