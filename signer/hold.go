package signer

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"strconv"
	"strings"
	"sync"

	"github.com/blockcypher/cryptosigner/signer/bitcoin"
	"github.com/blockcypher/cryptosigner/util"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rlp"
	"golang.org/x/crypto/sha3"
)

// Signer interface
type Signer interface {
	NewKey() (pub, priv []byte, err error)
	Sign(private, data []byte) ([]byte, error)
}

// KeyHold interface
type KeyHold interface {
	// Creates and keeps a new key pair. Unlocking it to produce a signature will require that the data
	// to sign pass the provided challenge.
	NewKey(challenge Challenge, prefix byte) (addr string, err error)

	// For a given source address and data that should pass the challenge provided when address keys were
	// created, signs that data.
	Sign(addr string, data []byte)
}

// Internal representation of the coin family, address, public key and private key trifecta. The private key
// is still encrypted at this stage.
type key struct {
	coinFamily       CoinFamily
	address          string
	encryptedPrivate []byte
	challenge        Challenge
}

func readKey(data []byte) *key {
	parts := bytes.Split(data, []byte{32}) // space
	// check for old format
	var k key
	if len(parts) == 3 {
		k.coinFamily = BitcoinFamily
		k.address = string(parts[0])
		k.encryptedPrivate, _ = hex.DecodeString(string(parts[1]))
		challng, _ := hex.DecodeString(string(parts[2]))
		k.challenge = ReadChallenge(challng, k.coinFamily)
	} else {
		coinFamily, _ := strconv.Atoi(string(data[0]))
		k.coinFamily = CoinFamily(uint8(coinFamily))
		k.address = string(parts[1])
		k.encryptedPrivate, _ = hex.DecodeString(string(parts[2]))
		challng, _ := hex.DecodeString(string(parts[3]))
		k.challenge = ReadChallenge(challng, k.coinFamily)
	}
	return &k
}

func (k *key) bytes() []byte {
	data := new(bytes.Buffer)
	data.WriteString(strconv.Itoa(int(k.coinFamily)))
	data.WriteString(" ")
	data.WriteString(k.address)
	data.WriteString(" ")
	data.WriteString(hex.EncodeToString(k.encryptedPrivate))
	data.WriteString(" ")
	data.WriteString(hex.EncodeToString(k.challenge.Bytes()))
	return data.Bytes()
}

// Hold holds the keys and handles their lifecycle. Decrypts the private key just for the time of
// computing a signature.
type Hold struct {
	cipher     cipher.Block
	cipherlock *sync.Mutex
	store      Store
	signer     Signer
	keys       map[string]*key
}

// MakeHold create the hold structure
func MakeHold(pass string, store Store, signer Signer) (*Hold, error) {
	// hash the password to make a 32-bytes cipher key
	passh := sha256.Sum256([]byte(pass))
	cipher, err := aes.NewCipher(passh[:])
	if err != nil {
		return nil, err
	}
	data, err := store.ReadAll()
	if err != nil {
		return nil, err
	}

	keys := readKeyData(data)
	return &Hold{cipher, new(sync.Mutex), store, signer, keys}, nil
}

// NewKey creates a new keypair and save it in the hold
func (h *Hold) NewKey(challenge Challenge, prefix byte, family CoinFamily) (string, error) {
	pub, priv, err := h.signer.NewKey()
	if err != nil {
		return "", err
	}
	var addr string
	switch family {
	case BitcoinFamily:
		addr = bitcoin.EncodeAddress(util.Hash160(pub), prefix)
	case EthereumFamily:
		// Ethereum addresses are the last 20 bytes of the SHA3-256 of the pubkey
		shaSum := sha3.Sum256(pub)
		addrBytes := shaSum[0:20]
		addr = strings.ToLower(hex.EncodeToString(addrBytes))
	default:
		return "", errors.New("Unknown coin family")
	}

	enc, err := util.Encrypt(h.cipher, priv)
	if err != nil {
		return "", err
	}
	newkey := &key{
		coinFamily:       family,
		address:          addr,
		encryptedPrivate: enc,
		challenge:        challenge}
	h.keys[addr] = newkey
	return addr, h.store.Save(string(addr), newkey.bytes())
}

// Sign an address iff the challenge pass
func (h *Hold) Sign(addr string, data []byte) ([]byte, []byte, error) {
	key := h.keys[addr]
	if key == nil {
		return nil, nil, errors.New("Unknown address: " + addr)
	}
	if !key.challenge.Check(data) {
		return nil, nil, errors.New("challenge failed")
	}

	h.cipherlock.Lock()
	defer h.cipherlock.Unlock()

	clone := make([]byte, len(key.encryptedPrivate))
	copy(clone, key.encryptedPrivate)

	priv, err := util.Decrypt(h.cipher, clone)
	if err != nil {
		return nil, nil, err
	}

	pubkey := util.PubKeyFromPrivate(priv)

	switch key.coinFamily {
	case BitcoinFamily:
		// data passed is the digested tx bytes to sign, what we sign is the double-sha of that
		sigBytes := append(data, []byte{1, 0, 0, 0}...)
		sig, err := h.signer.Sign(priv, util.DoubleHash(sigBytes))
		return sig, pubkey, err
	case EthereumFamily:
		var tx *types.Transaction
		if err := rlp.DecodeBytes(data, &tx); err != nil {
			return nil, nil, err
		}
		epriv, err := crypto.ToECDSA(priv)
		if err != nil {
			return nil, nil, err
		} else if epriv == nil {
			return nil, nil, errors.New("Invalid private key")
		}
		config := params.MainnetChainConfig
		s := types.MakeSigner(config, config.EIP158Block)
		hash := s.Hash(tx)
		stx, err := types.SignTx(tx, s, epriv)
		sts := types.Transactions{stx}
		rawTx := hex.EncodeToString(sts.GetRlp(0))
		fmt.Println("rawtx", rawTx)
		msg, err := tx.AsMessage(types.NewEIP155Signer(tx.ChainId()))
		if err != nil {
			log.Fatal(err)
		}

		fmt.Println("from:", msg.From().Hex())
		sig, err := h.signer.Sign(priv, hash[:])
		//sig, err := crypto.Sign(h[:], epriv)
		return sig, pubkey, err

		//sigBytes :=
	default:
		return nil, nil, errors.New("Unknown coin family")
	}

}

func readKeyData(data [][]byte) map[string]*key {
	keys := make(map[string]*key)
	for _, kd := range data {
		key := readKey(kd)
		log.Println("Loaded address", key.address, "family", key.coinFamily)
		keys[key.address] = key
	}
	return keys
}
