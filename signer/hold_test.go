package signer

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/blockcypher/cryptosigner/util"
)

// Test-only in-memory key store
type TestStore struct {
	store map[string][]byte
}

func MakeTestStore() *TestStore {
	return &TestStore{make(map[string][]byte)}
}

func (ts *TestStore) ReadAll() ([][]byte, error) {
	values := make([][]byte, 0, len(ts.store))
	for _, value := range ts.store {
		values = append(values, value)
	}
	return values, nil
}

func (ts *TestStore) Save(key string, data []byte) error {
	ts.store[key] = data
	return nil
}

func (ts *TestStore) Delete(key string) error {
	delete(ts.store, key)
	return nil
}

const (
	ADDR1   = "15qx9ug952GWGTNn7Uiv6vode4RcGrRemh"
	ADDR2   = "1GGwoLVX9XVPfmpyPbkXxmXMBQDJSBai42"
	TxData1 = "0100000001000000000000000000000000000000000000000000000000000000000000000000000000" +
		"1976a9143522825adbc8908d47943b356bf789e4fad20b1c88ac000000000100f2052a010000001976" +
		"a9143522825adbc8908d47943b356bf789e4fad20b1c88ac00000000"
	TxData2 = "0100000001000000000000000000000000000000000000000000000000000000000000000000000000" +
		"1976a914a78ddeb84ba308abb780429d1bcdebce20a153fb88ac000000000100f2052a010000001976" +
		"a914a78ddeb84ba308abb780429d1bcdebce20a153fb88ac00000000"
	ADDR3   = "bc1qumnwpsyz0sresdl6yv4e7qlrg6nq0uy5vvdtrw"
	TxData3 = "0100000001f26efab8144d394209a4369de8082a3e6b55c28e067270c4add9e92c296411ba01000000" +
		"1976a9145dc74f0505b74972666dfc198378116c5690c88f88acffffffff" +
		"0174b601000000000016" +
		"0014e6e6e0c0827c079837fa232b9f03e346a607f09400000000"
	ADDR4   = "bc1qumnwpsyz0sresdl6yv4e7qlrg6nq0uy5vvdtrw"
	TxData4 = "0100000001d7c49537b0fa277701df8438ee845ff511132b4d9e7f95c7ca67782d701a285e0d000000" +
		"1976a9142425082fa769c0b853059fdab67d32c8c204c14c88acffffffff" +
		"01641400000000000016" +
		"0014e6e6e0c0827c079837fa232b9f03e346a607f09400000000"
)

func TestSig(t *testing.T) {
	fmt.Println("-----------------------")
	hold := testHold()
	sig, _, err := testNewAndSign(t, hold, ADDR1, TxData1)
	if err != nil {
		t.Error(err)
	}
	if len(sig) < 50 {
		t.Error("Invalid sig.")
	}

	sig, _, err = testNewAndSign(t, hold, ADDR2, TxData2)
	if err != nil {
		t.Error(err)
	}
	if len(sig) < 50 {
		t.Error("Invalid sig.")
	}
}

func TestSigFailChallenge(t *testing.T) {
	hold := testHold()
	sig, _, err := testNewAndSign(t, hold, ADDR2, TxData1)
	if err == nil || sig != nil {
		t.Error("Challenge should have failed.")
	}
	if err.Error() != "challenge failed" {
		t.Error("Unexpected error.")
	}
}

func TestSigBech32(t *testing.T) {
	hold := testHold()
	sig, _, err := testNewAndSign(t, hold, ADDR3, TxData3)
	if err != nil {
		t.Error(err)
	}
	if len(sig) < 50 {
		t.Error("Invalid sig.")
	}
}

func TestSigBech322(t *testing.T) {
	hold := testHold()
	sig, _, err := testNewAndSign(t, hold, ADDR4, TxData4)
	if err != nil {
		t.Error(err)
	}
	if len(sig) < 50 {
		t.Error("Invalid sig.")
	}
}

func testHold() *Hold {
	signer := &util.ECDSASigner{}
	store := MakeTestStore()
	hold, _ := MakeHold("test", store, signer)
	return hold
}

func testNewAndSign(t *testing.T, hold *Hold, targetAddr string, txhex string) ([]byte, []byte, error) {
	targetAddrs := []string{targetAddr}
	addr, err := hold.NewKey(NewSignatureChallenge(targetAddrs, BitcoinFamily), 0, BitcoinFamily)
	if err != nil {
		t.Error(err)
	}
	txData, _ := hex.DecodeString(txhex)
	return hold.Sign(addr, txData)
}
