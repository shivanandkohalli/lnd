package discovery

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math/rand"
	"reflect"
	"sync"
	"time"

	"github.com/btcsuite/btcd/btcec"
	"github.com/coreos/bbolt"
	"github.com/lightningnetwork/lnd/channeldb"
	"github.com/lightningnetwork/lnd/htlcswitch"
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

	prefixMutex sync.RWMutex
	// The prefix embeddings of all the nodes which are connected
	// Warning: All the connected nodes will have an extra coordinate, thus
	// strip the last coordinate and use it (This wont be the problem with
	// current node)
	// TODO (shiva): Fix the above issue
	currentPrefixEmbedding map[uint32][]uint32

	// List of nodes stored as a map who sent their prefix's in the current
	// processing cycle
	receivedPrefixNodes map[uint32]struct{}
	// function to send message to a peer where the peer is identified
	// by the sha256 hash of its public key
	sendToPeer func(pubKeyHash uint32, msg lnwire.Message) error

	// FetchLightningNode attempts to look up a target node by its identity
	// public key. channeldb.ErrGraphNodeNotFound is returned if the node
	// doesn't exist within the graph.
	fetchLightningNode func(routing.Vertex) (*channeldb.LightningNode, error)
	// This is the random 4 byte number(generated for every node that has
	// opened a channel) that will be appended with the current prefix
	// embedding of this node and sent to it.
	randomNodeCoordinate map[uint32]uint32

	// Stores a unique ID and a LightningPayment description until the dynamic
	// information is probed along the route.
	// This is only stored by the Initiator node
	dynamicInfoTable map[uint32]*routing.LightningPayment

	// Stores ID -> NodeID
	// When upstream query message is sent, this table stores the ID and the
	// NodeID which sent the message. It will be used again when forwarding
	// the downstream message
	dynamicInfoFrwdTable map[uint32]uint32

	// When a payment is initated, the probe ID is mapped to the keys required
	// for error decryption. Stored at the source node
	probeErrorPrivKeyMapping map[uint32]*ErrorDecryptor

	// When a payment is initated, the probe ID is mapped to the pub keys required
	// for error decryption. Stored at the destination node
	probeErrorPubKeyMapping map[uint32]*lnwire.ProbeInitMess
	// Channel to receive the dynamic info probe queries
	dynInfoProbeChan chan lnwire.DynamicInfoProbeMess

	// Channel to send the collected result from the dynamic info probe
	dynInfoResultChan chan lnwire.DynamicInfoProbeMess

	// To know the how much bandwidth/amount is present between the channel edge
	queryBandwidth func(edge *channeldb.ChannelEdgeInfo) lnwire.MilliSatoshi

	// function to send message to a peer where the peer is identified
	// by its node pubkey
	sendToPeerByPubKey func(target *btcec.PublicKey, msg ...lnwire.Message) error
	rand               *rand.Rand

	quit chan struct{}
}

type errorType byte

const (

	// no error
	errorNone errorType = 0
	// One of the nodes in the path is unable to fetch the node announcemnt
	// of the next node in the path
	errorNoNextNode = 1

	// A probe with the same ID already is exists, try resending the probe
	// with a different ID
	errorDuplicateProbe = 2

	// unable to decode the destination coordinates/embedding
	errorDestDecoding = 3

	// no sufficient capacity in the path
	errorNoSufficientCapacity = 4

	// TODO (shiva): Create more specific errors
	errorProbeDynamicInfo = 5

	// Error in updating the fees
	errorFeeUpdate = 6
)

// ErrorDecryptor to store the keys for error decryption of the messages.
type ErrorDecryptor struct {
	ProbeID   uint32
	ErrorKey1 *btcec.PrivateKey
	ErrorKey2 *btcec.PrivateKey
}

func (c errorType) string() string {
	switch c {
	case errorNone:
		return "errorNone"
	case errorNoNextNode:
		return "errorNoNextNode"
	case errorDuplicateProbe:
		return "errorDuplicateProbe"

	case errorDestDecoding:
		return "errorDestDecoding"

	case errorNoSufficientCapacity:
		return "errorNoSufficientCapacity"

	case errorProbeDynamicInfo:
		return "errorProbeDynamicInfo"

	case errorFeeUpdate:
		return "errorFeeUpdate"
	default:
		return "errorUnkown"
	}
}

func (s *speedyMurmursGossip) stop() {
	close(s.quit)
}

// NewSpeedyMurmurGossip ....
func newSpeedyMurmurGossip(nodeID uint32, spannTree *spanningTreeIdentity, broadCast func(skips map[routing.Vertex]struct{},
	msg ...lnwire.Message) error, sendToPeer func(pubKeyHash uint32, msg lnwire.Message) error, fetchLightningNode func(routing.Vertex) (*channeldb.LightningNode, error), bandwidth func(edge *channeldb.ChannelEdgeInfo) lnwire.MilliSatoshi, sendToPeerByPubKey func(target *btcec.PublicKey, msg ...lnwire.Message) error) *speedyMurmursGossip {
	// TODO (shiva): Find a way that this channel gets assigned in their
	// respective 'new' Methods
	spannTree.processRecEmbChan = make(chan bool)
	return &speedyMurmursGossip{
		smGossipChan:             make(chan lnwire.PrefixEmbedding),
		processRecEmbChan:        spannTree.processRecEmbChan,
		broadcast:                broadCast,
		nodeID:                   nodeID,
		spannTree:                spannTree,
		currentPrefixEmbedding:   make(map[uint32][]uint32),
		receivedPrefixNodes:      make(map[uint32]struct{}),
		randomNodeCoordinate:     make(map[uint32]uint32),
		rand:                     rand.New(rand.NewSource(time.Now().UnixNano())),
		sendToPeer:               sendToPeer,
		fetchLightningNode:       fetchLightningNode,
		dynamicInfoTable:         make(map[uint32]*routing.LightningPayment),
		dynamicInfoFrwdTable:     make(map[uint32]uint32),
		probeErrorPrivKeyMapping: make(map[uint32]*ErrorDecryptor),
		probeErrorPubKeyMapping:  make(map[uint32]*lnwire.ProbeInitMess),
		dynInfoProbeChan:         make(chan lnwire.DynamicInfoProbeMess),
		dynInfoResultChan:        make(chan lnwire.DynamicInfoProbeMess),
		queryBandwidth:           bandwidth,
		sendToPeerByPubKey:       sendToPeerByPubKey,
		quit:                     make(chan struct{}),
	}
}

func (s *speedyMurmursGossip) initEmbedding() {
	// var initEmbedding []uint32
	// s.currentPrefixEmbedding[s.nodeID] = initEmbedding
}

func (s *speedyMurmursGossip) getPrefixEmbedding() []uint32 {
	s.prefixMutex.RLock()
	defer s.prefixMutex.RUnlock()
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

	retvalEmb, err := s.IntToByteArray(currEmb[:], s.randomNodeCoordinate[nodeID])

	return retvalEmb, err
}

func (s *speedyMurmursGossip) copyInt(a []uint32) {
	temp := make([]uint32, len(a))
	copy(temp, a)
	s.currentPrefixEmbedding[s.nodeID] = temp
}

// Processes gossip messages related to SpeedyMurmurs
// Initiates to process messages related to dynamic info probing
// Note: This MUST be run as a goroutine
func (s *speedyMurmursGossip) startGossip() {
	s.initEmbedding()
	go s.processDynProbeInfo()
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
			log.Infof("Current root port node is %d", rootPortNode)
			if ok {
				s.prefixMutex.Lock()

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
					t, err := s.IntToByteArray(s.currentPrefixEmbedding[s.nodeID], r)
					if err != nil {
						log.Infof("Error in converting int to byte array %v", err)
					}
					mess := lnwire.NewPrefixEmbedding(s.nodeID, t)
					err = s.sendToPeer(nodeID, mess)
					if err != nil {
						log.Infof("Error Unable to send the embedding to %d", nodeID)
					}
				}

				s.prefixMutex.Unlock()
			}

			for k := range s.receivedPrefixNodes {
				delete(s.receivedPrefixNodes, k)
			}
		// Update the map with the latest gossip received
		case m := <-s.smGossipChan:
			t, err := s.ByteToIntArray(m.Embedding[:])
			if err != nil {
				log.Infof("Error in decoding received embedding, Error: %v", err)
				continue
			}

			temp := make([]uint32, len(t))
			copy(temp, t)
			s.prefixMutex.Lock()
			s.currentPrefixEmbedding[m.NodeID] = temp
			s.prefixMutex.Unlock()
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

// ByteToIntArray converts a byte array of size 'embeddingByteSize'
// to an intger array until it finds the first zero in the array
func (s *speedyMurmursGossip) ByteToIntArray(b []byte) ([]uint32, error) {
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

// IntToByteArray Converts an uint32 slice to a byte slice.
// if appendInt is not 0, it gets appended to the byte slice else neglected
// Returns byte slize of size 'embeddingByteSize'
func (s *speedyMurmursGossip) IntToByteArray(a []uint32, appendInt uint32) ([]byte, error) {

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

// func (s *speedyMurmursGossip) GetNextHop(dest []uint32, payment *routing.LightningPayment) (routing.Hop, error) {
// 	s.prefixMutex.RLock()
// 	defer s.prefixMutex.RUnlock()

// 	// To store the next hop parameters. To be returned
// 	var nextHop routing.Hop
// 	var minDist uint8
// 	minDist = math.MaxUint8
// 	for nodeID, emb := range s.currentPrefixEmbedding {
// 		dist := calcHopDistance(dest, emb)
// 		if dist < minDist {
// 			minDist = dist
// 			nodePubKey, err := s.spannTree.getPubKeyFromHash(nodeID)
// 			if err != nil {
// 				log.Infof("Failed to retrieve pubkey for the node ID %d", nodeID)
// 				continue
// 			}
// 			node, err := s.fetchLightningNode(routing.NewVertex(nodePubKey))
// 			if err != nil {
// 				log.Infof("Error while fetching Lighting node %v", err)
// 				continue
// 			}

// 			// TODO(shiva): Validate whether this function loops through only the
// 			// channels connecting to source or all?
// 			err = node.ForEachChannel(nil, func(_ *bbolt.Tx, chanInfo *channeldb.ChannelEdgeInfo,
// 				_, inEdge *channeldb.ChannelEdgePolicy) error {

// 				// If there is no edge policy for this candidate
// 				// node, skip.
// 				if inEdge == nil {
// 					return nil
// 				}

// 				nodeFee := computeFee(payment.Amount, inEdge)
// 				amtToSend := payment.Amount + nodeFee
// 				err := checkAmtValid(amtToSend, chanInfo, inEdge)
// 				if err != nil {
// 					log.Infof("%v", err)
// 				} else {
// 					// TODO(shiva): Calculate the full path fees and CLTV here
// 					nextHop.AmtToForward = amtToSend
// 					nextHop.OutgoingTimeLock = uint32(*payment.FinalCLTVDelta)
// 					nextHop.ChannelID = chanInfo.ChannelID
// 					nextHop.PubKeyBytes = routing.NewVertex(nodePubKey)
// 				}
// 				return nil
// 			})
// 		}
// 	}
// 	return nextHop, nil
// }

func (s *speedyMurmursGossip) GetNextHop(dest []byte, amount lnwire.MilliSatoshi) (htlcswitch.ForwardingInfo, error) {

	destEmbedding, err := s.ByteToIntArray(dest)
	if err != nil {
		return htlcswitch.ForwardingInfo{}, err
	}
	node, err := s.getNextNodeInRoute(destEmbedding, amount)
	if err != nil {
		return htlcswitch.ForwardingInfo{}, err
	}

	if node == nil {
		log.Infof("Destination forwarding info")
		return htlcswitch.ForwardingInfo{NextHop: htlcswitch.ExitHop, AmountToForward: amount}, nil
	}

	fwdInfo, err := s.isSufficientCapacity(amount, node)
	return fwdInfo, err
}

// Find the next node in the path to the destination
// returns LightningNode, nil if it finds
// returns nil, nil if this is the destination node
// returns nil, err if there is any error
func (s *speedyMurmursGossip) getNextNodeInRoute(dest []uint32, amt lnwire.MilliSatoshi) (*channeldb.LightningNode, error) {
	s.prefixMutex.RLock()
	defer s.prefixMutex.RUnlock()

	var minDist uint8
	// Assign the distance from this node to destination to the minDist as
	// the next node in the path Must have a lesser distance than this value
	minDist = calcHopDistance(dest, s.getPrefixEmbedding())
	var nextNode *channeldb.LightningNode

	// Checking if the destination is this node itself
	if reflect.DeepEqual(dest, s.getPrefixEmbedding()) {
		return nextNode, nil
	}

	for nodeID, emb := range s.currentPrefixEmbedding {

		// skip if the nodeID is that of current node
		if nodeID == s.nodeID {
			continue
		}
		// Truncating the last coordinate due to the way coordinates are stored
		// Refer 'currentPrefixEmbedding'
		if len(emb) > 0 {
			emb = emb[:len(emb)-1]
		}
		dist := calcHopDistance(dest, emb)
		if dist < minDist {

			nodePubKey, err := s.spannTree.getPubKeyFromHash(nodeID)
			if err != nil {
				log.Infof("Failed to retrieve pubkey for the node ID %d", nodeID)
				continue
			}
			node, err := s.fetchLightningNode(routing.NewVertex(nodePubKey))
			if err != nil {
				log.Infof("Error while fetching Lighting node %v", err)
				continue
			}
			_, err = s.isSufficientCapacity(amt, node)

			if err == nil {
				nextNode = node
				minDist = dist
			}
		}
	}

	if nextNode == nil {
		log.Infof("Node address, Destination address %v %v", s.getPrefixEmbedding(), dest)
		log.Infof("Map values %v", s.currentPrefixEmbedding)
		return nil, errors.New("Error, Unable to find the next hop speedymurmurs")
	}
	// _, err := nextNode.PubKey()
	// if err != nil {
	// 	return nil, errors.New("Error fetching pubkey")
	// }
	return nextNode, nil
}

// calcHopDistance, calculate the hop distance according to the prefix
// embeddings. Formula is:
// Distance to node A from root+ Distance to node B from root- 2*Common path from root
// The return value is of type uint8 as currently the embeddings can be a maximum of
// 20. Thus, the max path length will be 20 + 20 -2*0 = 40
func calcHopDistance(a []uint32, b []uint32) uint8 {
	commonPathLength := 0
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] != b[i] {
			break
		}
		commonPathLength++
	}

	hopDistance := uint8(len(a) + len(b) - 2*commonPathLength)

	return hopDistance
}

// computeFee computes the fee to forward an HTLC of `amt` milli-satoshis over
// the passed active payment channel. This value is currently computed as
// specified in BOLT07, but will likely change in the near future.
func computeFee(amt lnwire.MilliSatoshi,
	edge *channeldb.ChannelEdgePolicy) lnwire.MilliSatoshi {

	return edge.FeeBaseMSat + (amt*edge.FeeProportionalMillionths)/1000000
}

func (s *speedyMurmursGossip) checkAmtValid(amtToSend lnwire.MilliSatoshi,
	info *channeldb.ChannelEdgeInfo, edge *channeldb.ChannelEdgePolicy) error {
	// If the estimated bandwidth of the channel edge is not able
	// to carry the amount that needs to be send, return error.

	bandwidth := s.queryBandwidth(info)
	log.Infof("Channel bandwidth is %d", bandwidth)
	if bandwidth < amtToSend {
		log.Infof("Error, channel capacity less than the amount to send required %d, but have %d", amtToSend, bandwidth)
		return errors.New("Error, channel capacity less than the amount to send required but have")
	}
	// If the amountToSend is less than the minimum required
	// amount, return error.￼￼￼
	if amtToSend < edge.MinHTLC {
		return errors.New("Error, amt to send less than Edge MinHTLC")
	}

	return nil
}

func (s *speedyMurmursGossip) ProbeDynamicInfo(dest []uint32, payment *routing.LightningPayment, probeID uint32) (lnwire.DynamicInfoProbeMess, error) {

	log.Infof("ProbeDynamicInfo for destination address %v", dest)
	// TODO (shiva): Check if the payment is already added in the table

	errDecryptor, ok := s.probeErrorPrivKeyMapping[probeID]
	if !ok {
		log.Info("Error, do not have error keys corresponding to probeID")
		return lnwire.DynamicInfoProbeMess{}, errors.New("Error, do not have error keys corresponding to probeID")
	}
	r := probeID
	// TODO (shiva): Add locks here
	s.dynamicInfoTable[r] = payment

	// payment.Amount = payment.Amount + (payment.Amount)/1000
	nextNode, err := s.getNextNodeInRoute(dest, payment.Amount)
	if err != nil {
		return lnwire.DynamicInfoProbeMess{}, err
	}

	if nextNode == nil {
		return lnwire.DynamicInfoProbeMess{}, errors.New("This is the destination node")
	}

	// Check if any channel to the 'nextNode' has sufficient balance
	// to make the payment
	_, err = s.isSufficientCapacity(payment.Amount, nextNode)
	if err != nil {
		log.Infof("Error ProbeDynamicInfo %v", err)
	}
	// Converting the destination uint slice to byte slice for sending
	// it to the next node in route
	b, err := s.IntToByteArray(dest[:], 0)
	if err != nil {
		log.Infof("Error while converting 'ProbeDynamicInfo' %v", err)
	}
	mess := lnwire.NewDynamicInfoProbeMess(s.nodeID, r, payment.Amount, 0, 0, b, 0, 1, errDecryptor.ErrorKey1.PubKey())
	log.Infof("Sender, error probe %v %v", errDecryptor.ErrorKey1.PubKey(), errDecryptor.ErrorKey2.PubKey())

	// Adding the CLTV delta for the destination node, as the sender has
	// received this information from the invoice. The other CLTV deltas
	// will be aggregated during the
	if payment.FinalCLTVDelta == nil {
		mess.CLTVAggregator = routing.DefaultFinalCLTVDelta
	} else {
		mess.CLTVAggregator = uint32(*payment.FinalCLTVDelta)
	}
	nodePubKeyHash := pubKeyHash(nextNode.PubKeyBytes)

	// Check if the next node itself the destination for the payment,
	// then we need not send the probe
	s.prefixMutex.RLock()
	nextNodePrefix, ok := s.currentPrefixEmbedding[nodePubKeyHash]
	s.prefixMutex.RUnlock()

	if !ok {
		log.Infof("Error, next node embedding not found")
		return *mess, errors.New("next node embedding not found")
	}
	// Truncating the last coordinate due to the way coordinates are stored
	// Refer 'currentPrefixEmbedding'
	if len(nextNodePrefix) > 0 {
		nextNodePrefix = nextNodePrefix[:len(nextNodePrefix)-1]
	}

	n, _ := s.IntToByteArray(nextNodePrefix[:], 0)
	if reflect.DeepEqual(b, n) {
		log.Infof("No need to send probe, next node is destination")
		// TODO (shiva): Add locks here
		// Remove the current Probe ID from our table as we dont need it now
		delete(s.dynamicInfoTable, mess.ProbeID)
		return *mess, nil
	}

	log.Infof("dest %v, nextNode %v %d    %d", dest, nextNodePrefix, len(dest), len(nextNodePrefix))
	log.Infof("Sending dynamic probe to %d", nodePubKeyHash)
	err = s.sendToPeer(nodePubKeyHash, mess)
	if err != nil {
		log.Infof("Failed to send message to peer %v", err)
		return lnwire.DynamicInfoProbeMess{}, err
	}

	// Wait for the probe result/ until a timeout
	// TODO (shiva): Configure the timeout
	select {
	case m := <-s.dynInfoResultChan:
		if errorType(m.ErrorFlag) != errorNone {
			log.Infof("Error code received is %d", m.ErrorFlag)
			return m, errors.New(errorType(m.ErrorFlag).string())
		}
		return m, nil
	}

}

// Checks if there exists a channel to the 'nextNode' with atleast the
// capacity of 'amt'
func (s *speedyMurmursGossip) isSufficientCapacity(amt lnwire.MilliSatoshi, nextNode *channeldb.LightningNode) (htlcswitch.ForwardingInfo, error) {

	var chanFound = false
	var fwdInfo htlcswitch.ForwardingInfo
	selfNode, err := s.fetchLightningNode(routing.NewVertex(s.spannTree.selfPubKey))
	if err != nil {
		return fwdInfo, err
	}

	err = selfNode.ForEachChannel(nil, func(_ *bbolt.Tx, chanInfo *channeldb.ChannelEdgeInfo,
		outEdge, _ *channeldb.ChannelEdgePolicy) error {

		// If one channel has been found which can satisfy the condition, there is
		// no need to iterate over others
		if chanFound == true {
			return nil
		}
		// If there is no edge policy for this candidate
		// node, skip.
		if outEdge == nil {
			log.Info("No outEdge found while channel iteration")
			return nil
		}

		// if !reflect.DeepEqual(nextNode, outEdge.Node) {
		// 	return nil
		// }
		// Checking if the channel belongs to the 'nextNode' in question
		if !reflect.DeepEqual(nextNode.PubKeyBytes, chanInfo.NodeKey1Bytes) &&
			!reflect.DeepEqual(nextNode.PubKeyBytes, chanInfo.NodeKey2Bytes) {
			log.Info("Next node not matching")
			return nil
		}

		log.Infof("Outgoing channel for the next node found")
		// log.Infof("%v", selfNode.PubKeyBytes)
		// log.Infof("%v", nextNode.PubKeyBytes)
		// log.Infof("%v", chanInfo.NodeKey1Bytes)
		// log.Infof("%v", chanInfo.NodeKey2Bytes)
		// nodeFee := computeFee(payment.Amount, inEdge)
		// amtToSend := payment.Amount + nodeFee
		err := s.checkAmtValid(amt, chanInfo, outEdge)
		if err != nil {
			log.Infof("Error %v", err)
		} else {
			chanFound = true
			fwdInfo.NextHop = lnwire.NewShortChanIDFromInt(chanInfo.ChannelID)
			fwdInfo.AmountToForward = amt - computeFee(amt, outEdge)
			fwdInfo.OutgoingCTLV = uint32(outEdge.TimeLockDelta)
		}
		return nil
	})

	if chanFound == false {
		return fwdInfo, errors.New("No channel found with sufficient balance")
	}
	return fwdInfo, nil

}

func (s *speedyMurmursGossip) sendErrorToPeer(e errorType, m lnwire.DynamicInfoProbeMess) error {

	log.Infof("Sending error %d to peer", errorType(m.ErrorFlag))
	// start sending the message to the downstream peer, as
	// it is intended to reach the initiator of this probe
	m.IsUpstream = 0
	m.ErrorFlag = byte(e)
	// m.NodeID is the downstream peer who sent this message
	err := s.sendToPeer(m.NodeID, &m)
	if err != nil {
		log.Infof("Error in sending errormessage to downstream peer")
	}
	return err
}

// Note: This MUST be run as a goroutine
// This goroutine handles upstream and downstream probe info query
// TODO (shiva): Handle all the errors and propogate it to the source
func (s *speedyMurmursGossip) processDynProbeInfo() {
	for {
		select {
		case m := <-s.dynInfoProbeChan:
			// Upstream message
			if m.IsUpstream == 1 {
				if _, ok := s.dynamicInfoFrwdTable[m.ProbeID]; ok {
					log.Infof("Error duplicate probe message sent")
					s.sendErrorToPeer(errorDuplicateProbe, m)
					continue
				}

				dest, err := s.ByteToIntArray(m.Destination[:])
				if err != nil {
					log.Infof("Error while decoding dest address probe message %v", err)
					continue
				}

				s.prefixMutex.RLock()
				// Check if the current node itself the destination
				retval := reflect.DeepEqual(s.currentPrefixEmbedding[s.nodeID][:], dest[:])
				s.prefixMutex.RUnlock()
				if retval {

					errKeys, ok := s.probeErrorPubKeyMapping[m.ProbeID]
					if !ok {
						// Send error that destination has not received the pubkey mappings
						log.Infof("Error, destination has not received the error pubkey")
						continue
					}
					log.Infof("Dynamic probe message reached destination, reverting back to sender")
					m.Amount = errKeys.Amount
					m.ErrorPubKey = errKeys.ErrorKey2
					// Initiate downstream message
					m.IsUpstream = 0

					m.Amount = 10000 * 1000
					// m.NodeID is the sender who sent this message
					s.sendToPeer(m.NodeID, &m)
					continue
				}

				nextNode, err := s.getNextNodeInRoute(dest, m.Amount)
				if err != nil {
					log.Infof("Error while getting information about next node in route %v", err)
					s.sendErrorToPeer(errorNoNextNode, m)
					continue
				}
				// Check if any channel to the 'nextNode' has sufficient balance
				// to make the payment
				_, err = s.isSufficientCapacity(m.Amount, nextNode)
				if err != nil {
					log.Infof("Error ProbeDynamicInfo %v", err)
					s.sendErrorToPeer(errorProbeDynamicInfo, m)
					continue
				}

				// Storing the sender information and probeID, useful during downstream
				// message processing
				s.dynamicInfoFrwdTable[m.ProbeID] = m.NodeID
				// Updating the nodeID with the one who will be sending this
				// upstream message.
				m.NodeID = s.nodeID
				s.sendToPeer(pubKeyHash(nextNode.PubKeyBytes), &m)

			} else if m.IsUpstream == 0 { // Downstream message

				// Check if this probe was initiated by current node
				_, ok := s.dynamicInfoTable[m.ProbeID]
				if ok {
					// Update the fee information
					err := s.updateFee(&m)
					if err != nil {
						log.Infof("Error in updating fee %v", err)

					}
					log.Infof("Dynamic probe successfully reached sender, aggregated fee %d, CLTV aggregatd %d, Error pubkey %v", m.Amount, m.CLTVAggregator, m.ErrorPubKey)
					// Send the probe result on the channel for the one who is waiting for it
					select {
					case s.dynInfoResultChan <- m:
					}

					// TODO (shiva): Add Write locks here
					delete(s.dynamicInfoTable, m.ProbeID)
					continue
				}

				nodeID, ok := s.dynamicInfoFrwdTable[m.ProbeID]
				if !ok {
					log.Infof("Error ProbeID for the query not present in table")
					continue
				}

				if errorType(m.ErrorFlag) == errorNone {
					// Update the fee information in the message only if there is
					// no error
					err := s.updateFee(&m)
					if err != nil {
						log.Infof("Error in updating fee %v", err)
						m.ErrorFlag = errorFeeUpdate
					}
				}
				// Just forward the message downstream without modifying anything
				err := s.sendToPeer(nodeID, &m)
				if err != nil {
					log.Infof("Error in forwarding message downstream %v", err)
				}
				// Remove the ID from the table
				delete(s.dynamicInfoFrwdTable, m.ProbeID)

			} else {
				log.Infof("Error IsUpstream value unkown")
			}
		}
	}
}

// Calculates the fees and timelock value for the next node in the path
// and updates the received 'DynamicInfoProbeMess' with appropriate values
func (s *speedyMurmursGossip) updateFee(m *lnwire.DynamicInfoProbeMess) error {

	// Check if the next node in the path is the destination
	// If yes, then do not aggregate the fees as no fee is charged for final hop
	dest, err := s.ByteToIntArray(m.Destination[:])
	if err != nil {
		return err
	}
	nextNode, err := s.getNextNodeInRoute(dest, m.Amount)
	if err != nil {
		return err
	}
	s.prefixMutex.RLock()
	nextNodePrefix, ok := s.currentPrefixEmbedding[pubKeyHash(nextNode.PubKeyBytes)]
	s.prefixMutex.RUnlock()

	if !ok {
		log.Infof("Error, next node embedding not found")
	}
	// Truncating the last coordinate due to the way coordinates are stored
	// Refer 'currentPrefixEmbedding'
	if len(nextNodePrefix) > 0 {
		nextNodePrefix = nextNodePrefix[:len(nextNodePrefix)-1]
	}
	log.Infof("Dest: %v", dest)
	log.Infof("Next: %v", nextNodePrefix)
	if reflect.DeepEqual(dest, nextNodePrefix) {
		log.Infof("Update fee, destination node")
		return nil
	}

	log.Infof("Update fee, aggregating fee")

	selfNode, err := s.fetchLightningNode(routing.NewVertex(s.spannTree.selfPubKey))
	if err != nil {
		return err
	}

	var chanFound = false

	err = selfNode.ForEachChannel(nil, func(_ *bbolt.Tx, chanInfo *channeldb.ChannelEdgeInfo,
		outEdge, chanPolicy *channeldb.ChannelEdgePolicy) error {

		if chanFound == true {
			return nil
		}
		// If there is no edge policy for this candidate
		// node, skip.
		if outEdge == nil {
			log.Info("No outEdge found while channel iteration")
			return nil
		}

		// log.Infof("%v", selfNode.PubKeyBytes)
		// log.Infof("%v", nextNode.PubKeyBytes)
		// log.Infof("%v", chanInfo.NodeKey1Bytes)
		// log.Infof("%v", chanInfo.NodeKey2Bytes)
		// Checking if the channel belongs to the 'nextNode' in question
		if !reflect.DeepEqual(nextNode.PubKeyBytes, chanInfo.NodeKey1Bytes) &&
			!reflect.DeepEqual(nextNode.PubKeyBytes, chanInfo.NodeKey2Bytes) {
			log.Info("Next node not matching")
			return nil
		}
		// if !reflect.DeepEqual(nextNode, outEdge.Node) {
		// 	return nil
		// }
		log.Info("Next node matched")

		// log.Infof("%v", selfNode.PubKeyBytes)
		// log.Infof("%v", nextNode.PubKeyBytes)
		// log.Infof("%v", chanInfo.NodeKey1Bytes)
		// log.Infof("%v", chanInfo.NodeKey2Bytes)

		// TODO (shiva): Check if there is enough funds in the channel
		// nodeFee := computeFee(payment.Amount, inEdge)
		// amtToSend := payment.Amount + nodeFee

		m.Amount = m.Amount + computeFee(m.Amount, chanPolicy)
		m.CLTVAggregator = m.CLTVAggregator + uint32(chanPolicy.TimeLockDelta)
		chanFound = true
		log.Infof("Updated amt, cltv %d, %d", m.Amount, m.CLTVAggregator)
		return nil
	})

	if chanFound == false {
		return errors.New("No channel found with sufficient balance")
	}
	return nil
}

func pubKeyHash(pubKeyBytes [33]byte) uint32 {
	tempByteHash := sha256.Sum256(pubKeyBytes[:])
	return binary.BigEndian.Uint32(tempByteHash[:])
}

func (s *speedyMurmursGossip) SendInvoiceProbeInfo(IdentityKey *btcec.PublicKey) (uint32, error) {
	probeID := s.rand.Uint32()

	k1, _ := btcec.NewPrivateKey(btcec.S256())
	k2, _ := btcec.NewPrivateKey(btcec.S256())

	e := &ErrorDecryptor{
		ProbeID:   probeID,
		ErrorKey1: k1,
		ErrorKey2: k2,
	}

	_, ok := s.probeErrorPrivKeyMapping[probeID]
	if ok {
		log.Infof("SendInvoiceProbeInfo already existing in the map")
		return 0, errors.New("SendInvoiceProbeInfo already existing in the map")
	}
	s.probeErrorPrivKeyMapping[probeID] = e

	m := &lnwire.ProbeInitMess{
		ProbeID:    probeID,
		NodePubKey: s.spannTree.selfPubKey,
		ErrorKey1:  e.ErrorKey1.PubKey(),
		ErrorKey2:  e.ErrorKey2.PubKey(),
	}
	err := s.sendToPeerByPubKey(IdentityKey, m)

	if err != nil {
		log.Infof("Error, SendInvoiceProbeInfo while sending message %v", err)
	}
	//TODO: Store info probeID -> key1,key2
	return probeID, err
}

func (s *speedyMurmursGossip) ReceiveInvoiceProbeInfo(m *lnwire.ProbeInitMess) error {
	log.Infof("SpeedyMurmurs, received *lnwire.ProbeInitMess")
	s.probeErrorPubKeyMapping[m.ProbeID] = m
	return nil
}
