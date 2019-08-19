package discovery

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/routing"
)

func mockBroadcast(skips map[routing.Vertex]struct{},
	msg ...lnwire.Message) error {
	return nil
}
func mockSendToPeer(pubKeyHash uint32, msg lnwire.Message) error {
	return nil
}
func TestStartGossip(t *testing.T) {
	spannTreeID := newSpanTreeIdentity(nodeKeyPub1, mockBroadcast)
	s := newSpeedyMurmurGossip(spannTreeID.nodeSpanTree.nodeID, spannTreeID, mockBroadcast, mockSendToPeer, nil, nil, nil)

	s.spannTree.rootPortNode = 1
	go s.startGossip()
	s.registerPeer(1)
	a := make([]uint32, 1)
	a[0] = 500
	b, _ := s.IntToByteArray(a, 5000)
	mess := lnwire.NewPrefixEmbedding(1, b)

	select {
	case s.smGossipChan <- *mess:
	}

	select {
	case s.processRecEmbChan <- true:
	}
	time.Sleep(time.Millisecond * 500)
	s.stop()

	r := s.getPrefixEmbedding()
	if r[0] != 500 || r[1] != 5000 {
		t.Fatalf("Failed to acquired embedding from root port %v", r)
	}
}
func TestCopyInt(t *testing.T) {
	spannTreeID := newSpanTreeIdentity(nodeKeyPub1, nil)
	smGossip := newSpeedyMurmurGossip(spannTreeID.nodeSpanTree.nodeID, spannTreeID, nil, nil, nil, nil, nil)

	a := make([]uint32, 3)
	a[0] = 1
	a[1] = 2
	a[2] = 3
	smGossip.copyInt(a)
	r := smGossip.getPrefixEmbedding()
	if len(a) == len(r) {
		for i := range a {
			if a[i] != r[i] {
				t.Fatalf("%v", r)
			}
		}
	} else {
		t.Fatalf("Unequal length %v", r)
	}
}
func TestInitEmbedding(t *testing.T) {
	spannTreeID := newSpanTreeIdentity(nodeKeyPub1, nil)
	smGossip := newSpeedyMurmurGossip(spannTreeID.nodeSpanTree.nodeID, spannTreeID, nil, nil, nil, nil, nil)

	smGossip.initEmbedding()
	e := smGossip.getPrefixEmbedding()

	if len(e) != 0 {
		t.Fatalf("Inital embedding is not size 0 %d", len(e))
	}
}
func TestRegisterPeer(t *testing.T) {
	spannTreeID := newSpanTreeIdentity(nodeKeyPub1, nil)
	smGossip := newSpeedyMurmurGossip(spannTreeID.nodeSpanTree.nodeID, spannTreeID, nil, nil, nil, nil, nil)
	b, err := smGossip.registerPeer(5)
	if err != nil {
		t.Fatalf("Error in registering %v", err)
	} else {
		t.Logf("%v", b)
	}

	r, _ := smGossip.ByteToIntArray(b)
	if len(r) != 1 {
		t.Fatalf("%v", r)
	}

	b, err = smGossip.registerPeer(5)
	if err == nil {
		t.Fatal("Unable to detect peer already registerd")
	}
}

func TestIntToByteArray(t *testing.T) {

	spannTreeID := newSpanTreeIdentity(nodeKeyPub1, nil)
	smGossip := newSpeedyMurmurGossip(spannTreeID.nodeSpanTree.nodeID, spannTreeID, nil, nil, nil, nil, nil)
	testInt := make([]uint32, 2)
	testInt[0] = 1234
	testInt[1] = 9812

	b, err := smGossip.IntToByteArray(testInt, 7897779)
	if err != nil {
		t.Fatalf("Error returned %v", err)
	}

	r, err := smGossip.ByteToIntArray(b)

	if r[0] != 1234 || r[1] != 9812 || r[2] != 7897779 {
		t.Fatalf("Failed to encode and decode %v", r[0])
	}

	testInt = make([]uint32, 21)
	_, err = smGossip.IntToByteArray(testInt, 0)
	if err == nil {
		t.Fatal("Failed to detect size overflow error")
	}

	_, err = smGossip.IntToByteArray(testInt[0:20], 4564)
	if err == nil {
		t.Fatal("Failed to detect size overflow error")
	}

	var a []uint32
	x, _ := smGossip.IntToByteArray(a, 500)
	y, _ := smGossip.ByteToIntArray(x)

	if y[0] != 500 {
		t.Fatalf("Error when first parameter is nil %v", y)
	}

}
func TestByteToIntArray(t *testing.T) {

	spannTreeID := newSpanTreeIdentity(nodeKeyPub1, nil)
	smGossip := newSpeedyMurmurGossip(spannTreeID.nodeSpanTree.nodeID, spannTreeID, nil, nil, nil, nil, nil)
	var test [80]byte
	_, error := smGossip.ByteToIntArray(test[:50])
	if error == nil {
		t.Fatal("Unable to detect size mismatch")
	}

	buf := new(bytes.Buffer)
	var num uint32
	num = 12349879
	binary.Write(buf, binary.LittleEndian, num)
	temp := buf.Bytes()
	// copy temp to test byte
	for i := 0; i < len(temp); i++ {
		test[i] = temp[i]
	}
	buf = new(bytes.Buffer)
	num = 97892134
	binary.Write(buf, binary.LittleEndian, num)
	temp = buf.Bytes()
	// copy temp to test byte
	for i := 0; i < len(temp); i++ {
		test[i+4] = temp[i]
	}
	x, err := smGossip.ByteToIntArray(test[:])

	if err != nil {
		t.Fatal("Error returned")
	}
	if len(x) != 2 {
		t.Fatalf("Int array not equal to desired length: %d %v", len(x), x)
	}

	if x[0] != 12349879 && x[1] != 97892134 {
		t.Logf("%d", x[0])
		t.Fatal("Error in decoding to int array")
	}
}

func TestCalcHopDistance(t *testing.T) {
	a := []uint32{1, 2, 1}
	b := []uint32{1, 3, 1}

	retval := calcHopDistance(a, b)
	if retval != 4 {
		t.Fatalf("Incorrect hop distance calculated")
	}

	a = []uint32{1, 2, 1}
	b = []uint32{3, 1}

	retval = calcHopDistance(a, b)
	if retval != 5 {
		t.Fatalf("Incorrect hop distance calculated")
	}

	a = []uint32{}
	b = []uint32{5, 23423, 1234, 111, 42342, 111234, 34}

	retval = calcHopDistance(a, b)
	if retval != 7 {
		t.Fatalf("Incorrect hop distance calculated")
	}

	a = make([]uint32, 20)
	b = make([]uint32, 20)

	for i := 0; i < 20; i++ {
		a[i] = uint32(i)
		b[i] = uint32(i)
	}

	retval = calcHopDistance(a, b)
	if retval != 0 {
		t.Fatalf("Incorrect hop distance calculated")
	}

	for i := 0; i < 20; i++ {
		a[i] = uint32(i)
		b[i] = uint32(i + 1)
	}

	retval = calcHopDistance(a, b)
	if retval != 40 {
		t.Fatalf("Incorrect hop distance calculated")
	}

	a[0] = 1
	b[0] = 1

	a[1] = 2
	b[1] = 2

	retval = calcHopDistance(a, b)
	if retval != 36 {
		t.Fatalf("Incorrect hop distance calculated")
	}

}

func TestEncryptionScheme(t *testing.T) {
	// failure := &lnwire.FailUnknownNextPeer{}
	failure := &lnwire.FailFinalIncorrectCltvExpiry{CltvExpiry: 55}

	remoteKey, _ := btcec.NewPrivateKey(btcec.S256())

	cipherText, err := EncryptError(failure, remoteKey.PubKey())

	t.Logf("Length is %d", len(cipherText.Reason))
	if err != nil {
		t.Fatalf("Encryption error %v", err)
	}

	plainText, err := DecryptError(cipherText, remoteKey)

	if err != nil {
		t.Fatalf("DecryptError error %v", err)
	}

	switch plainText.(type) {
	// If the end destination didn't know they payment
	// hash, then we'll terminate immediately.
	case *lnwire.FailFinalIncorrectCltvExpiry:
		t.Log("Pass CLTV")
	default:
		t.Fatalf("Failed")
	}

}
