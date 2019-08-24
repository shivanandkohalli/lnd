package lnwire

import (
	"testing"

	"github.com/btcsuite/btcd/btcec"
)

func TestKeySerialize(t *testing.T) {
	k, _ := btcec.NewPrivateKey(btcec.S256())
	b := k.PubKey().SerializeCompressed()
	t.Logf("%v", k.PubKey())
	n, _ := btcec.ParsePubKey(b[:], btcec.S256())
	t.Logf("%v", n)
	t.Fatal("asdfadf")
}
