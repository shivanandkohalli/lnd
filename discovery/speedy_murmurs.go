package discovery

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math/rand"
	"time"

	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/routing"
)

const embeddingByteSize = 80

type speedyMurmursGossip struct {
	smGossipChan chan lnwire.PrefixEmbedding
	// This is a signal from the spanning tree that, it has completed its
	// processing of received messages, now, the received embeddings can
	// be processed
	processRecEmbChan chan bool
	// Broadcast broadcasts a particular set of announcements to all peers
	// that the daemon is connected to. If supplied, the exclude parameter
	// indicates that the target peer should be excluded from the
	// broadcast.
	broadcast func(skips map[routing.Vertex]struct{},
		msg ...lnwire.Message) error
	// This ID is assigned by the spanning tree protocol, (This will be
	// nothing but the hash of the lighting public key)
	nodeID uint32
	// spannTree will provide information about the current state of the
	// spanning tree
	spannTree *spanningTreeIdentity

	currentPrefixEmbedding map[uint32][]uint32

	// List of nodes stored as a map who sent their prefix's in the current
	// processing cycle
	receivedPrefixNodes map[uint32]struct{}
	// function to send message to a peer where the peer is identified
	// by the sha256 hash of its public key
	sendToPeer func(pubKeyHash uint32, msg lnwire.Message) error

	// This is the random 4 byte number(generated for every node that has
	// opened a channel) that will be appended with the current prefix
	// embedding of this node and sent to it.
	randomNodeCoordinate map[uint32]uint32

	rand *rand.Rand

	quit chan struct{}
}

func (s *speedyMurmursGossip) stop() {
	close(s.quit)
}

// NewSpeedyMurmurGossip ....
func newSpeedyMurmurGossip(nodeID uint32, spannTree *spanningTreeIdentity, broadCast func(skips map[routing.Vertex]struct{},
	msg ...lnwire.Message) error, sendToPeer func(pubKeyHash uint32, msg lnwire.Message) error) *speedyMurmursGossip {
	// TODO (shiva): Find a way that this channel gets assigned in their
	// respective 'new' Methods
	spannTree.processRecEmbChan = make(chan bool)
	return &speedyMurmursGossip{
		smGossipChan:           make(chan lnwire.PrefixEmbedding),
		processRecEmbChan:      spannTree.processRecEmbChan,
		broadcast:              broadCast,
		nodeID:                 nodeID,
		spannTree:              spannTree,
		currentPrefixEmbedding: make(map[uint32][]uint32),
		receivedPrefixNodes:    make(map[uint32]struct{}),
		randomNodeCoordinate:   make(map[uint32]uint32),
		rand:                   rand.New(rand.NewSource(time.Now().UnixNano())),
		sendToPeer:             sendToPeer,
		quit:                   make(chan struct{}),
	}
}

func (s *speedyMurmursGossip) initEmbedding() {
	// var initEmbedding []uint32
	// s.currentPrefixEmbedding[s.nodeID] = initEmbedding
}

func (s *speedyMurmursGossip) getPrefixEmbedding() []uint32 {
	return s.currentPrefixEmbedding[s.nodeID]
}

func (s *speedyMurmursGossip) registerPeer(nodeID uint32) ([]byte, error) {

	_, ok := s.randomNodeCoordinate[nodeID]
	if ok {
		return nil, errors.New("Peer already registered")
	}

	// Generate a random number, and checking that it is not 0
	// 0 is used as the delimiter in the byte array to detect end
	r := s.rand.Uint32()
	for r == 0 {
		r = s.rand.Uint32()
	}
	s.randomNodeCoordinate[nodeID] = r
	currEmb := s.getPrefixEmbedding()

	if len(currEmb) >= embeddingByteSize/4 {
		return nil, errors.New("Embedding buffer full")
	}

	retvalEmb, err := s.intToByteArray(currEmb[:], s.randomNodeCoordinate[nodeID])

	return retvalEmb, err
}

func (s *speedyMurmursGossip) copyInt(a []uint32) {
	temp := make([]uint32, len(a))
	copy(temp, a)
	s.currentPrefixEmbedding[s.nodeID] = temp
}

// Note: This MUST be run as a goroutine
func (s *speedyMurmursGossip) startGossip() {
	s.initEmbedding()
	logTimer := time.NewTicker(10 * time.Second)
	for {
		select {
		// Wait for a signal from the spanning tree module to start
		// processing
		case <-s.processRecEmbChan:
			log.Infof("Totall received %d Prefix messages", len(s.receivedPrefixNodes))
			rootPortNode := s.spannTree.getRootPortID()
			_, ok := s.receivedPrefixNodes[rootPortNode]
			// We have received a new path embedding from the node
			// connected to the root port. Update our embedding to this
			// received value and broadcast to other nodes
			//log.Infof("Current root port node is %d", rootPortNode)
			if ok {
				temp := make([]uint32, len(s.currentPrefixEmbedding[rootPortNode]))
				copy(temp, s.currentPrefixEmbedding[rootPortNode])
				s.currentPrefixEmbedding[s.nodeID] = temp
				log.Infof("Received embedding from the root port %d %v %v", rootPortNode, s.currentPrefixEmbedding[s.nodeID], s.currentPrefixEmbedding[rootPortNode])
				for nodeID, r := range s.randomNodeCoordinate {
					// Not sending to ourself
					if nodeID == s.nodeID {
						log.Info("Not sending to myself")
						continue
					}
					t, err := s.intToByteArray(s.currentPrefixEmbedding[s.nodeID], r)
					if err != nil {
						log.Infof("Error in converting int to byte array %v", err)
					}
					mess := lnwire.NewPrefixEmbedding(s.nodeID, t)
					err = s.sendToPeer(nodeID, mess)
					if err != nil {
						log.Infof("Unable to send the embedding to %d", nodeID)
					}
				}
			}

			for k := range s.receivedPrefixNodes {
				delete(s.receivedPrefixNodes, k)
			}
		// Update the map with the latest gossip received
		case m := <-s.smGossipChan:
			t, err := s.byteToIntArray(m.Embedding[:])
			if err != nil {
				log.Infof("Error in decoding received embedding, Error: %v", err)
				continue
			}

			temp := make([]uint32, len(t))
			copy(temp, t)
			s.currentPrefixEmbedding[m.NodeID] = temp
			s.receivedPrefixNodes[m.NodeID] = struct{}{}
			//log.Infof("Path embeddings received from %d %v %v", m.NodeID, t, s.currentPrefixEmbedding[m.NodeID])
		case <-logTimer.C:
			log.Infof("Speedy Embedding %v", s.getPrefixEmbedding())
		// Received a signal to quit, returing from the goroutine
		case <-s.quit:
			log.Info("Received a signal to quit, exiting speedy murmurs")
			return
		}
	}

}

func (s *speedyMurmursGossip) byteToIntArray(b []byte) ([]uint32, error) {
	if len(b) != embeddingByteSize {
		return nil, errors.New("Size of received byte array isn't equal to desired size")
	}
	var intArray []uint32
	var decodedInt uint32
	for i := 0; i < embeddingByteSize; i = i + 4 {
		buf := new(bytes.Buffer)
		buf.Write(b[i : i+4])
		binary.Read(buf, binary.LittleEndian, &decodedInt)
		// 0 is the delimitter here, process until we reach it.
		if decodedInt == 0 {
			break
		}
		intArray = append(intArray, decodedInt)
	}
	return intArray[:], nil
}

func (s *speedyMurmursGossip) intToByteArray(a []uint32, appendInt uint32) ([]byte, error) {

	if appendInt == 0 && len(a) > embeddingByteSize/4 {
		return nil, errors.New("Size overflow")
	} else if len(a) >= embeddingByteSize/4 {
		return nil, errors.New("Size overflow")
	}
	byteArray := make([]byte, embeddingByteSize)
	for i, val := range a {
		buf := new(bytes.Buffer)
		binary.Write(buf, binary.LittleEndian, val)
		t := buf.Bytes()
		for j := 0; j < 4; j++ {
			byteArray[i*4+j] = t[j]
		}
	}
	if appendInt != 0 {
		buf := new(bytes.Buffer)
		binary.Write(buf, binary.LittleEndian, appendInt)
		t := buf.Bytes()
		appendPos := (len(a)) * 4
		for j := 0; j < 4; j++ {
			byteArray[appendPos+j] = t[j]
		}
	}
	return byteArray, nil
}
