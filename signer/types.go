package signer

// CoinFamily is an enum to describe the family of coin
type CoinFamily uint8

const (
	// BitcoinFamily type (btc, ltc, bcy,doge ...)
	BitcoinFamily CoinFamily = iota
	// EthereumFamily type (eth, beth...)s
	EthereumFamily
	// UnknownCoinFamily for error purpose
	UnknownCoinFamily
)

// CoinPrefixToCoinFamily convert a coin family to a prefix
func CoinPrefixToCoinFamily(coinPrefix string) CoinFamily {
	switch coinPrefix {
	case "btc", "ltc", "doge":
		return BitcoinFamily
	case "eth":
		return EthereumFamily
	default:
		return UnknownCoinFamily
	}
}
