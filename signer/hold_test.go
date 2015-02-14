package signer

import (
  "encoding/hex"
  "testing"
)

const (
  ADDR1    = "15qx9ug952GWGTNn7Uiv6vode4RcGrRemh"
  ADDR2    = "1GGwoLVX9XVPfmpyPbkXxmXMBQDJSBai42"
  TX_DATA1 = "0100000001000000000000000000000000000000000000000000000000000000000000000000000000"+
             "1976a9143522825adbc8908d47943b356bf789e4fad20b1c88ac000000000100f2052a010000001976"+
             "a9143522825adbc8908d47943b356bf789e4fad20b1c88ac00000000"
  TX_DATA2 = "0100000001000000000000000000000000000000000000000000000000000000000000000000000000"+
             "1976a914a78ddeb84ba308abb780429d1bcdebce20a153fb88ac000000000100f2052a010000001976"+
             "a914a78ddeb84ba308abb780429d1bcdebce20a153fb88ac00000000"
)

func TestSig(t *testing.T) {
  hold := testHold()
  sig, _, err := testNewAndSign(t, hold, ADDR1, TX_DATA1)
  if err != nil { t.Error(err) }
  if len(sig) < 50 { t.Error("Invalid sig.") }

  sig, _, err = testNewAndSign(t, hold, ADDR2, TX_DATA2)
  if err != nil { t.Error(err) }
  if len(sig) < 50 { t.Error("Invalid sig.") }
}

func TestSigFailChallenge(t *testing.T) {
  hold := testHold()
  sig, _, err := testNewAndSign(t, hold, ADDR2, TX_DATA1)
  if err == nil || sig != nil { t.Error("Challenge should have failed.") }
  if err.Error() != "challenge failed" { t.Error("Unexpected error.") }
}

func testHold() *Hold {
  signer := &ECDSASigner{}
  store  := MakeTestStore()
  hold,_ := MakeHold("test", store, signer)
  return hold
}

func testNewAndSign(t *testing.T, hold *Hold, targetAddr string, txhex string) ([]byte, []byte, error) {
  addr, err := hold.NewKey(NewSignatureChallenge(targetAddr), 0)
  if err != nil { t.Error(err) }
  txData,_  := hex.DecodeString(txhex)
  return hold.Sign(addr, txData)
}
