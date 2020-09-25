package ethereum

import (
	"fmt"
	"strings"

	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"
)

// VerifyChallenge checks if the output contains the address
func VerifyChallenge(addresses []string, toSign []byte) bool {
	var tx *types.Transaction
	if err := rlp.DecodeBytes(toSign, &tx); err != nil {
		fmt.Println(err)
		return false
	}
	if len(addresses) != 1 {
		// something wrong there is no change for Ethereum
		return false
	}

	// remove the 0x
	toAddress := strings.ToLower(tx.To().Hex()[2:])
	return addresses[0] == toAddress
}
