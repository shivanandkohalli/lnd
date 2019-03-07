package discovery

import (
	"crypto/sha256"
	"encoding/binary"
	"time"

	"github.com/btcsuite/btcd/btcec"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/routing"
)

// The interval at which the hello messages must be processed in seconds.
const cfgProcessHelloDelay = 5

type spanningTreeHello struct {
	nodeID     uint32
	rootNodeID uint32
	costToRoot uint32
}

// spanninTreeIdentity is a struct to hold the nodes spanning tree related data,
// hello messages received from other nodes, and
type spanningTreeIdentity struct {
	// Nodes spanning tree config data
	nodeSpanTree spanningTreeHello
	// Channel to receive hello messages sent by other nodes
	spanTreeChan chan spanningTreeHello
	// To store the hello messages for processing
	receivedHelloMessage []spanningTreeHello
	// Stores list of connected nodes along with the states, format is
	// "Node Serialized Public Key":"State"
	// State description
	// "R" -> Root node path
	// "D" -> Designated node
	// "B" -> Blocked node
	connectedNodeState map[uint32]string
	// To store the Hello message having the best path to the root node
	bestMessage spanningTreeHello
	// Store a map of hash of pubkey with that of pubkey,
	connectedNodePubkey map[uint32]routing.Vertex
	// Interval at which the hello messages received must be processed.
	processHelloDelay time.Duration
	// Broadcast broadcasts a particular set of announcements to all peers
	// that the daemon is connected to. If supplied, the exclude parameter
	// indicates that the target peer should be excluded from the
	// broadcast.
	broadcast func(skips map[routing.Vertex]struct{},
		msg ...lnwire.Message) error
	// To store the latest hello message sent by a connected node
	latestNodeHello map[uint32]spanningTreeHello
	// A signal to trigger the processing of the received prefix embedding
	// according to the speedy murmurs algorithm
	processRecEmbChan chan bool
	// Store the node ID of the node connected to the root port
	rootPortNode uint32
}

func newSpanTreeIdentity(selfKey *btcec.PublicKey, broadCast func(skips map[routing.Vertex]struct{},
	msg ...lnwire.Message) error) *spanningTreeIdentity {
	log.Info("New spanning tree created")
	// Convert the node public key to Sha256 hash of 32 bit integer
	tempByteHash := sha256.Sum256(selfKey.SerializeCompressed())
	selfKeyHash := binary.BigEndian.Uint32(tempByteHash[:])
	return &spanningTreeIdentity{
		nodeSpanTree: spanningTreeHello{
			nodeID:     selfKeyHash,
			rootNodeID: selfKeyHash, // Initially all the nodes assume they are the root
			costToRoot: 0},          // As the nodes think they are the root, cost to itself is 0
		bestMessage: spanningTreeHello{
			nodeID:     selfKeyHash,
			rootNodeID: selfKeyHash, // Initially all the nodes assume they are the root
			costToRoot: 0},          // As the nodes think they are the root, cost to itself is 0
		spanTreeChan:        make(chan spanningTreeHello),
		connectedNodeState:  make(map[uint32]string),
		connectedNodePubkey: make(map[uint32]routing.Vertex),
		latestNodeHello:     make(map[uint32]spanningTreeHello),
		processHelloDelay:   time.Second * cfgProcessHelloDelay,
		broadcast:           broadCast,
		rootPortNode:        selfKeyHash,
	}
}

// Note: This MUST be run as a goroutine
// Starts sending and processing the HelloMessages for constructing the spanning
// tree
func (s *spanningTreeIdentity) buildSpanningTree() {
	processHelloTimer := time.NewTicker(s.processHelloDelay)
	logTimer := time.NewTicker(10 * time.Second)
	defer processHelloTimer.Stop()
	for {
		select {
		// Received a new HelloMessage, append it in the slice so that all the
		// messages collected will be processed at once
		case helloMess := <-s.spanTreeChan:
			log.Infof("Received spanning tree hello message %d %d %d", helloMess.nodeID, helloMess.rootNodeID, helloMess.costToRoot)
			if s.latestNodeHello[helloMess.nodeID] != helloMess {
				s.receivedHelloMessage = append(s.receivedHelloMessage, helloMess)
				s.latestNodeHello[helloMess.nodeID] = helloMess
			} else {
				log.Infof("Same hello received from %d again", helloMess.nodeID)
			}

		case <-processHelloTimer.C:
			log.Infof("Number of received messages %d", len(s.receivedHelloMessage))
			s.processHelloMessages()
			s.printSpanningTreeIdentities()
			// Send a signal to start processing the received prefix embeddings
			select {
			case s.processRecEmbChan <- true:
			}
		case <-logTimer.C:
			//	s.printSpanningTreeIdentities()
		}
	}
}

func (s *spanningTreeIdentity) processHelloMessages() {

	// To store the index of the message having the best root node
	bestRootIndex := -1

	//TODO: apply locks from here
	messLen := len(s.receivedHelloMessage)
	for i, h := range s.receivedHelloMessage {
		// The lower the root node Id, the better the path
		if h.rootNodeID < s.bestMessage.rootNodeID {
			//log.Infof("Found a better path h.rootNodeID < s.bestMessage.rootNodeID %d %d", h.rootNodeID, s.bestMessage.rootNodeID)
			s.bestMessage = h
			bestRootIndex = i
		} else if h.rootNodeID == s.bestMessage.rootNodeID {
			if h.costToRoot+1 < s.bestMessage.costToRoot {
				//log.Infof("Found a better path h.costToRoot < s.bestMessage.costToRoot %d %d", h.costToRoot, s.bestMessage.costToRoot)
				s.bestMessage = h
				bestRootIndex = i
			} else if h.costToRoot+1 == s.bestMessage.costToRoot {
				if h.nodeID < s.bestMessage.nodeID {
					//log.Infof("Found a better path h.nodeID < s.bestMessage.nodeID %d %d", h.nodeID, s.bestMessage.nodeID)
					s.bestMessage = h
					bestRootIndex = i
				}
			}
		}
	}
	// Update the current node information with the best paths if received
	if bestRootIndex != -1 {
		log.Infof("Found a better path to root Rootnode Id, Cost %d %d", s.receivedHelloMessage[bestRootIndex].rootNodeID, s.receivedHelloMessage[bestRootIndex].costToRoot+1)
		s.nodeSpanTree.rootNodeID = s.receivedHelloMessage[bestRootIndex].rootNodeID
		s.nodeSpanTree.costToRoot = s.receivedHelloMessage[bestRootIndex].costToRoot + 1
		// Updating the cost, as it will be required for comparision in the next iteration
		s.bestMessage.costToRoot = s.bestMessage.costToRoot + 1
		// Update the root node, and mark all other node paths as designated
		for k := range s.connectedNodeState {
			if k == s.nodeSpanTree.rootNodeID {
				continue
			}
			latestHello := s.latestNodeHello[k]
			if latestHello.rootNodeID == s.bestMessage.rootNodeID {
				if latestHello.costToRoot == s.bestMessage.costToRoot {
					if latestHello.nodeID < s.nodeSpanTree.nodeID {
						s.connectedNodeState[k] = "B"
					} else {
						s.connectedNodeState[k] = "D"
					}
				} else if latestHello.costToRoot+1 == s.bestMessage.costToRoot {
					s.connectedNodeState[k] = "B"
				}
			} else {
				s.connectedNodeState[k] = "D"
			}
		}

		_, ok := s.connectedNodeState[s.receivedHelloMessage[bestRootIndex].nodeID]
		if ok {
			s.connectedNodeState[s.receivedHelloMessage[bestRootIndex].nodeID] = "R"
			s.rootPortNode = s.receivedHelloMessage[bestRootIndex].nodeID
		} else {
			log.Info("Peer not registered in the spanning tree maps")
		}
		// Dessiminating the best path found to the connected nodes
		err := s.sendBestPathToConnectedNodes()
		if err != nil {
			log.Info("Unable to broadcast spanning tree hello messages")
		}
	} else {
		log.Info("Evaluating designated or blocked")
		for _, h := range s.receivedHelloMessage {
			if h.rootNodeID == s.nodeSpanTree.rootNodeID {
				if h.costToRoot == s.nodeSpanTree.costToRoot {
					if h.nodeID < s.nodeSpanTree.nodeID {
						s.connectedNodeState[h.nodeID] = "D"
					} else {
						s.connectedNodeState[h.nodeID] = "B"
					}
				} else if h.costToRoot+1 == s.nodeSpanTree.costToRoot {
					s.connectedNodeState[h.nodeID] = "B"
				}
			}
		}
	}

	//Removing the processed HelloMessages from the received buffer
	s.receivedHelloMessage = append(s.receivedHelloMessage[messLen:])
	//TODO apply locks till here
}

// func (s *spanningTreeIdentity) processHelloMessages() {

// 	// To store the index of the message having the best root node
// 	bestRootIndex := -1

// 	//TODO: apply locks from here
// 	messLen := len(s.receivedHelloMessage)
// 	for i, h := range s.receivedHelloMessage {

// 		if s.bestMessage == h {
// 			log.Info("Same message received")
// 			continue
// 		}
// 		// The lower the root node Id, the better the path
// 		if h.rootNodeID < s.bestMessage.rootNodeID {
// 			log.Infof("Found a better path h.rootNodeID < s.bestMessage.rootNodeID %d %d", h.rootNodeID, s.bestMessage.rootNodeID)
// 			s.bestMessage = h
// 			bestRootIndex = i
// 		} else if h.rootNodeID == s.bestMessage.rootNodeID {
// 			if h.costToRoot+1 < s.bestMessage.costToRoot {
// 				log.Infof("Found a better path h.costToRoot < s.bestMessage.costToRoot %d %d", h.costToRoot, s.bestMessage.costToRoot)
// 				s.bestMessage = h
// 				bestRootIndex = i
// 			} else if h.costToRoot+1 == s.bestMessage.costToRoot {
// 				if h.nodeID < s.bestMessage.nodeID {
// 					log.Infof("Found a better path h.nodeID < s.bestMessage.nodeID %d %d", h.nodeID, s.bestMessage.nodeID)
// 					s.bestMessage = h
// 					bestRootIndex = i
// 				}
// 			}
// 		}
// 	}
// 	// Update the current node information with the best paths if received
// 	if bestRootIndex != -1 {
// 		log.Infof("Found a better path to root Rootnode Id, Cost %d %d", s.receivedHelloMessage[bestRootIndex].rootNodeID, s.receivedHelloMessage[bestRootIndex].costToRoot+1)
// 		s.nodeSpanTree.rootNodeID = s.receivedHelloMessage[bestRootIndex].rootNodeID
// 		s.nodeSpanTree.costToRoot = s.receivedHelloMessage[bestRootIndex].costToRoot + 1
// 		// Updating the cost, as it will be required for comparision in the next iteration
// 		s.bestMessage.costToRoot = s.bestMessage.costToRoot + 1
// 		// Update the root node, and mark all other node paths as designated
// 		for k := range s.connectedNodeState {
// 			s.connectedNodeState[k] = "D"
// 		}

// 		_, ok := s.connectedNodeState[s.receivedHelloMessage[bestRootIndex].nodeID]
// 		if ok {
// 			s.connectedNodeState[s.receivedHelloMessage[bestRootIndex].nodeID] = "R"
// 		} else {
// 			log.Info("Peer not registered in the spanning tree maps")
// 		}
// 		// Dessiminating the best path found to the connected nodes
// 		err := s.sendBestPathToConnectedNodes()
// 		if err != nil {
// 			log.Info("Unable to broadcast spanning tree hello messages")
// 		}
// 	} else {
// 		log.Info("Evaluating designated or blocked")
// 		toSend := make(map[routing.Vertex]struct{})
// 		for _, h := range s.receivedHelloMessage {
// 			if s.bestMessage == h {
// 				continue
// 			}
// 			if h.rootNodeID > s.nodeSpanTree.rootNodeID {
// 				log.Info("Cond1")
// 				s.connectedNodeState[h.nodeID] = "D"
// 				toSend[s.connectedNodePubkey[h.nodeID]] = struct{}{}
// 			} else if h.rootNodeID == s.nodeSpanTree.rootNodeID {
// 				if h.costToRoot > s.nodeSpanTree.costToRoot+1 {
// 					log.Info("Cond2")
// 					s.connectedNodeState[h.nodeID] = "D"
// 					toSend[s.connectedNodePubkey[h.nodeID]] = struct{}{}
// 				} else if h.costToRoot == s.nodeSpanTree.costToRoot+1 {
// 					if h.nodeID > s.bestMessage.nodeID {
// 						// 	log.Info("Cond3")
// 						// 	s.connectedNodeState[h.nodeID] = "D"
// 						// 	toSend[s.connectedNodePubkey[h.nodeID]] = struct{}{}
// 						// } else {
// 						log.Info("Cond4")
// 						s.connectedNodeState[h.nodeID] = "B"
// 					} else {
// 						log.Info("Unkown cond")
// 					}
// 				} else if h.costToRoot == s.nodeSpanTree.costToRoot {
// 					if h.nodeID < s.nodeSpanTree.nodeID {
// 						log.Info("Cond5")
// 						s.connectedNodeState[h.nodeID] = "D"
// 						toSend[s.connectedNodePubkey[h.nodeID]] = struct{}{}
// 					} else {
// 						log.Info("Cond6")
// 						s.connectedNodeState[h.nodeID] = "B"
// 					}
// 				}
// 				// // If both the nodes have discovered the same root node ID, the path which is
// 				// // worse to the root node will be blocked.
// 				// if h.costToRoot > s.nodeSpanTree.costToRoot {
// 				// 	log.Infof("Found a block port h.costToRoot > s.nodeSpanTree.costToRoot %d %d", h.costToRoot, s.bestMessage.costToRoot)
// 				// 	_, ok := s.connectedNodeState[h.nodeID]
// 				// 	if ok {
// 				// 		s.connectedNodeState[h.nodeID] = "B"
// 				// 	} else {
// 				// 		log.Info("Unable to find the connected state for the node")
// 				// 	}
// 				// } else if h.costToRoot == s.nodeSpanTree.costToRoot {
// 				// 	if h.nodeID > s.nodeSpanTree.nodeID {
// 				// 		log.Infof("Found a block port h.nodeID > s.nodeSpanTree.nodeID %d %d", h.nodeID, s.bestMessage.nodeID)
// 				// 		_, ok := s.connectedNodeState[h.nodeID]
// 				// 		if ok {
// 				// 			s.connectedNodeState[h.nodeID] = "B"
// 				// 		} else {
// 				// 			log.Info("Unable to find the connected state for the node")
// 				// 		}
// 				// 	}
// 				// } else {
// 				// 	// This port will remain as "D", the other end of the port needs to be blocked.
// 				// 	// Inform the other end of the connected node.
// 				// }
// 			}
// 		}
// 		if len(toSend) > 0 {
// 			skip := make(map[routing.Vertex]struct{})
// 			for _, v := range s.connectedNodePubkey {
// 				_, ok := toSend[v]
// 				if !ok {
// 					skip[v] = struct{}{}
// 				}
// 			}
// 			m := &lnwire.SpanningTreeHello{
// 				NodeID:     s.nodeSpanTree.nodeID,
// 				RootNodeID: s.nodeSpanTree.rootNodeID,
// 				CostToRoot: s.nodeSpanTree.costToRoot,
// 			}
// 			s.broadcast(skip, m)
// 		}
// 	}
// 	//Removing the processed HelloMessages from the received buffer
// 	s.receivedHelloMessage = append(s.receivedHelloMessage[messLen:])
// 	//TODO apply locks till here
// }

// sendBestPathToConnectedNodes sends the current best path found to all the
// connected nodes in the state as Designated port 'D'
func (s *spanningTreeIdentity) sendBestPathToConnectedNodes() error {

	m := &lnwire.SpanningTreeHello{
		NodeID:     s.nodeSpanTree.nodeID,
		RootNodeID: s.nodeSpanTree.rootNodeID,
		CostToRoot: s.nodeSpanTree.costToRoot,
	}
	skip := make(map[routing.Vertex]struct{})
	for k, v := range s.connectedNodeState {
		if v != "D" {
			t, ok := s.connectedNodePubkey[k]
			if ok {
				skip[t] = struct{}{}
			} else {
				log.Info("Unable to find the pubkey before broadcasting")
			}
		}
	}

	err := s.broadcast(skip, m)
	return err
}

func (s *spanningTreeIdentity) sha256ByteArray(data []byte) uint32 {
	tempByteHash := sha256.Sum256(data)
	return binary.BigEndian.Uint32(tempByteHash[:])
}

func (s *spanningTreeIdentity) printSpanningTreeIdentities() {
	log.Infof("Node ID %d, Root node ID %d, Cost to Root node %d", s.nodeSpanTree.nodeID, s.nodeSpanTree.rootNodeID, s.nodeSpanTree.costToRoot)
	for k, v := range s.connectedNodeState {
		log.Infof("Connected node %d, State %s", k, v)
	}
}

// getRootPortID sends the ID of the node connected to the root port
func (s *spanningTreeIdentity) getRootPortID() uint32 {
	return s.rootPortNode
}
