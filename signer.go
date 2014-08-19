package main

import (
  "fmt"
  "log"
)

// start with password
// read/store keys from disk, associated with target pubkey
// http API: get pubkey for new target address, sign transaction with output for that address

type Store interface {
  Save(key string, data []byte) error
  Delete(key string) error
  ReadAll() ([][]byte, error)
}

type KeyHold interface {
  // Creates and keeps a new key pair. Unlocking it to produce a signature will require that the data
  // to sign pass the provided challenge.
  NewKey(challenge Challenge, prefix byte) (addr string, err error)

  // For a given source address and data that should pass the challenge provided when address keys were
  // created, signs that data.
  Sign(addr string, data []byte)
}

type Challenge interface {
  Check(tosign []byte) bool
  Bytes() []byte
}

type Signer interface {
  NewKey() (pub, priv []byte, err error)
  Sign(private, data []byte) ([]byte, error)
}

func main() {
  fmt.Print("Enter password: ")
  var pwd string
  fmt.Scanln(&pwd)
  if len(pwd) == 0 {
    log.Fatal("Could not read.")
  }

  signer := &ECDSASigner{}
  store, err := MakeFileStore()
  if err != nil { log.Println(err); return }

  hold, err := MakeHold(pwd, store, signer)
  if err != nil { log.Println(err); return }

  StartServer(hold)
}
