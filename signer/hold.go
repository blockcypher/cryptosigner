package signer

import (
  "bytes"
  "crypto/aes"
  "crypto/cipher"
  "encoding/hex"
  "errors"
  "log"
  "sync"
  //"io"
  //"crypto/rand"
  "code.google.com/p/go.crypto/scrypt"
)

const (
  scryptN     = 1 << 16
  scryptr     = 8
  scryptp     = 1
  scryptdkLen = 32
)


type KeyHold interface {
  // Creates and keeps a new key pair. Unlocking it to produce a signature will require that the data
  // to sign pass the provided challenge.
  NewKey(challenge Challenge, prefix byte) (addr string, err error)

  // For a given source address and data that should pass the challenge provided when address keys were
  // created, signs that data.
  Sign(addr string, data []byte)
}

// Internal representation of the address, public key and private key trifecta. The private key
// is still encrypted at this stage.
type key struct {
  address           string
  encryptedPrivate  []byte
  challenge         Challenge
}

func readKey(data []byte) *key {
  parts     := bytes.Split(data, []byte{32}) // space
  encpkey,_ := hex.DecodeString(string(parts[1]))
  challng,_ := hex.DecodeString(string(parts[2]))
  return &key{string(parts[0]), encpkey, ReadChallenge(challng)}
}

func (self *key) bytes() []byte {
  data := bytes.NewBuffer([]byte(self.address))
  data.WriteString(" ")
  data.WriteString(hex.EncodeToString(self.encryptedPrivate))
  data.WriteString(" ")
  data.WriteString(hex.EncodeToString(self.challenge.Bytes()))
  return data.Bytes()
}

// Holds the keys and handles their lifecycle. Decrypts the private key just for the time of
// computing a signature.
type Hold struct {
  cipher      cipher.Block
  cipherlock  *sync.Mutex
  store       Store
  signer      Signer
  keys        map[string]*key
}

func MakeHold(pass string, store Store, signer Signer) (*Hold, error) {
  // derive a 32-bytes cipher key using scrypt
  /* TODO: use real random salt and store it in key file
  salt := make([]byte, 32)
  _, err := io.ReadFull(rand.Reader, salt)
  if err != nil { return nil, err }
  */
  derivedKey, err := scrypt.Key([]byte(pass), []byte(pass), scryptN, scryptr, scryptp, scryptdkLen)
  if err != nil { return nil, err }

  cipher, err  := aes.NewCipher(derivedKey)
  if err != nil { return nil, err }
  data, err := store.ReadAll()
  if err != nil { return nil, err }

  keys := readKeyData(data)
  return &Hold{cipher, new(sync.Mutex), store, signer, keys}, nil
}

func (self *Hold) NewKey(challenge Challenge, prefix byte) (string, error) {
  pub, priv, err := self.signer.NewKey()
  if err != nil { return "", err }
  addr := EncodeAddress(hash160(pub), prefix)

  enc, err := encrypt(self.cipher, priv)
  if err != nil { return "", err }
  newkey := &key{addr, enc, challenge}
  self.keys[addr] = newkey
  return addr, self.store.Save(string(addr), newkey.bytes())
}

func (self *Hold) Sign(addr string, data []byte) ([]byte, []byte, error) {
  key   := self.keys[addr]
  if key == nil {
    return nil, nil, errors.New("Unknown address: " + addr)
  }
  if !key.challenge.Check(data) {
    return nil, nil, errors.New("challenge failed")
  }

  self.cipherlock.Lock()
  defer self.cipherlock.Unlock()

  clone := make([]byte, len(key.encryptedPrivate))
  copy(clone, key.encryptedPrivate)

  priv, err  := decrypt(self.cipher, clone)
  if err != nil { return nil, nil, err }

  pubkey := pubKeyFromPrivate(priv)

  // data passed is the digested tx bytes to sign, what we sign is the double-sha of that
  sigBytes := append(data, []byte{1, 0, 0, 0}...)
  sig, err := self.signer.Sign(priv, doubleHash(sigBytes))
  return sig, pubkey, err
}

func readKeyData(data [][]byte) map[string]*key {
  keys := make(map[string]*key)
  for _, kd := range data {
    key := readKey(kd)
    log.Println("Loaded address", key.address)
    keys[key.address] = key
  }
  return keys
}
