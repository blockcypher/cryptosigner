package util

// ECDSA signer implementation as well as various crypto-related utility functions.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"

	"github.com/btcsuite/btcd/btcec/v2/ecdsa"

	"github.com/btcsuite/btcd/btcec/v2"
	"golang.org/x/crypto/ripemd160"
)

// ECDSASigner the ECDSA signer struct
type ECDSASigner struct{}

// NewKey Generates a new keypair
func (eS *ECDSASigner) NewKey() ([]byte, []byte, error) {
	priv, err := btcec.NewPrivateKey()
	if err != nil {
		return nil, nil, err
	}
	pubkey := priv.PubKey()
	return pubkey.SerializeCompressed(), priv.ToECDSA().D.Bytes(), nil
}

// Sign data with a private key
func (eS *ECDSASigner) Sign(private, data []byte) ([]byte, error) {
	privkey, _ := btcec.PrivKeyFromBytes(private)

	sig := ecdsa.Sign(privkey, data)
	if sig == nil {
		return nil, errors.New("could not sign data")
	}
	return sig.Serialize(), nil
}

// PubKeyFromPrivate retrieve public key from a private key
func PubKeyFromPrivate(private []byte) []byte {
	_, pubkey := btcec.PrivKeyFromBytes(private)
	//pubkeyaddr  := &pubkey
	return pubkey.SerializeCompressed()
}

// Hash160 is SHA250 followed by RIPEMD160
func Hash160(data []byte) []byte {
	if len(data) == 1 && data[0] == 0 {
		data = []byte{}
	}
	h1 := sha256.Sum256(data)
	h2 := ripemd160.New()
	h2.Write(h1[:])
	return h2.Sum(nil)
}

// DoubleHash double SHA256
func DoubleHash(data []byte) []byte {
	h1 := sha256.Sum256(data)
	h2 := sha256.Sum256(h1[:])
	return h2[:]
}

// Encrypt data
func Encrypt(ciph cipher.Block, text []byte) ([]byte, error) {
	b := base64.StdEncoding.EncodeToString(text)
	ciphertext := make([]byte, aes.BlockSize+len(b))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}
	cfb := cipher.NewCFBEncrypter(ciph, iv)
	cfb.XORKeyStream(ciphertext[aes.BlockSize:], []byte(b))
	return ciphertext, nil
}

// Decrypt data
func Decrypt(ciph cipher.Block, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < aes.BlockSize {
		return nil, errors.New("ciphertext too short")
	}
	iv := ciphertext[:aes.BlockSize]
	cfb := cipher.NewCFBDecrypter(ciph, iv)
	text := ciphertext[aes.BlockSize:]
	cfb.XORKeyStream(text, text)
	data, err := base64.StdEncoding.DecodeString(string(text))
	if err != nil {
		return nil, err
	}
	return data, nil
}
