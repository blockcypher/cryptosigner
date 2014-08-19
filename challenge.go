package main

import (
  "bytes"
)

const (
  SIGNATURE_CHALLENGE = iota
)

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
  return bytes.Compare(decoded[1:21], tosign[len(tosign)-6-20:len(tosign)-6]) == 0
}

func (self *sigChallenge) Bytes() []byte {
  head := []byte{SIGNATURE_CHALLENGE}
  return append(head, []byte(self.address)...)
}
