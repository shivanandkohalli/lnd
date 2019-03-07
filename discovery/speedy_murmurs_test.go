package discovery

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"

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
	s := newSpeedyMurmurGossip(spannTreeID.nodeSpanTree.nodeID, spannTreeID, mockBroadcast, mockSendToPeer)

	s.spannTree.rootPortNode = 1
	go s.startGossip()
	s.registerPeer(1)
	a := make([]uint32, 1)
	a[0] = 500
	b, _ := s.intToByteArray(a, 5000)
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
	smGossip := newSpeedyMurmurGossip(spannTreeID.nodeSpanTree.nodeID, spannTreeID, nil, nil)

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
	smGossip := newSpeedyMurmurGossip(spannTreeID.nodeSpanTree.nodeID, spannTreeID, nil, nil)

	smGossip.initEmbedding()
	e := smGossip.getPrefixEmbedding()

	if len(e) != 0 {
		t.Fatalf("Inital embedding is not size 0 %d", len(e))
	}
}
func TestRegisterPeer(t *testing.T) {
	spannTreeID := newSpanTreeIdentity(nodeKeyPub1, nil)
	smGossip := newSpeedyMurmurGossip(spannTreeID.nodeSpanTree.nodeID, spannTreeID, nil, nil)
	b, err := smGossip.registerPeer(5)
	if err != nil {
		t.Fatalf("Error in registering %v", err)
	} else {
		t.Logf("%v", b)
	}

	r, _ := smGossip.byteToIntArray(b)
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
	smGossip := newSpeedyMurmurGossip(spannTreeID.nodeSpanTree.nodeID, spannTreeID, nil, nil)

	testInt := make([]uint32, 2)
	testInt[0] = 1234
	testInt[1] = 9812

	b, err := smGossip.intToByteArray(testInt, 7897779)
	if err != nil {
		t.Fatalf("Error returned %v", err)
	}

	r, err := smGossip.byteToIntArray(b)

	if r[0] != 1234 || r[1] != 9812 || r[2] != 7897779 {
		t.Fatalf("Failed to encode and decode %v", r[0])
	}

	testInt = make([]uint32, 21)
	_, err = smGossip.intToByteArray(testInt, 0)
	if err == nil {
		t.Fatal("Failed to detect size overflow error")
	}

	_, err = smGossip.intToByteArray(testInt[0:20], 4564)
	if err == nil {
		t.Fatal("Failed to detect size overflow error")
	}

	var a []uint32
	x, _ := smGossip.intToByteArray(a, 500)
	y, _ := smGossip.byteToIntArray(x)

	if y[0] != 500 {
		t.Fatalf("Error when first parameter is nil %v", y)
	}

}
func TestByteToIntArray(t *testing.T) {
	spannTreeID := newSpanTreeIdentity(nodeKeyPub1, nil)
	smGossip := newSpeedyMurmurGossip(spannTreeID.nodeSpanTree.nodeID, spannTreeID, nil, nil)
	var test [80]byte
	_, error := smGossip.byteToIntArray(test[:50])
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
	x, err := smGossip.byteToIntArray(test[:])

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
