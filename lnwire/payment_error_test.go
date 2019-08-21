package lnwire

import (
	"bytes"
	"testing"

	"github.com/btcsuite/btcd/btcec"
)

func TestPaymentError(t *testing.T) {
	var failure FailureMessage
	failure = FailInsufficientCapacity{}

	var b bytes.Buffer
	if err := EncodeFailure(&b, failure, 0); err != nil {
	}

	errorMessage := &PaymentError{}

	// errorMessage.Reason = make([]byte, b.Len())
	copy(errorMessage.Reason[:], b.Bytes())
	ephPrivKey, _ := btcec.NewPrivateKey(btcec.S256())
	errorMessage.ErrorPubKey = ephPrivKey.PubKey()
	errorMessage.ProbeID = 1

	var wm bytes.Buffer

	num, err := WriteMessage(&wm, errorMessage, 0)
	t.Logf("Number of bytes written %d", num)
	if err != nil {
		t.Fatalf("error in write message")
	}

	mess, err := ReadMessage(&wm, 0)
	if err != nil {
		t.Fatalf("error in read message")
	}

	switch mess.(type) {
	case *PaymentError:
		t.Logf("Pass")
	default:
		t.Fatalf("Failed")
	}
	t.Logf("Length is %d", len(errorMessage.Reason))
	// t.Fatal("asdf")

}
