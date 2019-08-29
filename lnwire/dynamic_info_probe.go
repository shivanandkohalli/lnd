package lnwire

import (
	"io"

	"github.com/btcsuite/btcd/btcec"
)

// EmbeddingSize this will be the absolute size of the path embeddings in byte
// TODO: Make it dynamic and not absolute
const EmbeddingSize = 80

// DynamicInfoProbeMess aims to collect the fees and cltv values along the route
// to the destination
// This struct implements the lnwire.Message interface
type DynamicInfoProbeMess struct {
	// NodeID sha256 hash of the public key of the sending node
	// during the upstream query
	NodeID uint32
	// ProbeId Unique ID for every dynamic probe created
	ProbeID        uint32
	Amount         MilliSatoshi
	CLTVAggregator uint32
	Destination    [EmbeddingSize]byte
	ErrorPubKey    *btcec.PublicKey
	ErrorFlag      byte
	IsUpstream     uint8
	PathLength     uint8
}

// NewDynamicInfoProbeMess creates new instance of the probe message
func NewDynamicInfoProbeMess(nodeID uint32, probeID uint32, amt MilliSatoshi,
	cltvAggregator uint32, dest []byte, errorFlag uint8, isUpstream uint8, key *btcec.PublicKey, pathlength uint8) *DynamicInfoProbeMess {
	mess := DynamicInfoProbeMess{
		NodeID:         nodeID,
		ProbeID:        probeID,
		Amount:         amt,
		CLTVAggregator: cltvAggregator,
		ErrorFlag:      errorFlag,
		IsUpstream:     isUpstream,
		ErrorPubKey:    key,
		PathLength:     pathlength,
	}

	copy(mess.Destination[:], dest)
	return &mess
}

// Decode deserializes a serialized DynamicInfoProbeMess message stored in the
// passed io.Reader
//
// This is part of the lnwire.Message interface.
func (s *DynamicInfoProbeMess) Decode(r io.Reader, pver uint32) error {
	return ReadElements(r,
		&s.NodeID,
		&s.ProbeID,
		&s.Amount,
		&s.CLTVAggregator,
		s.Destination[:],
		&s.ErrorPubKey,
		&s.ErrorFlag,
		&s.IsUpstream,
		&s.PathLength,
	)
}

// Encode serializes the target SpanningTreeHello into the passed io.Writer
//
// This is part of the lnwire.Message interface.
func (s *DynamicInfoProbeMess) Encode(w io.Writer, pver uint32) error {
	return WriteElements(w,
		s.NodeID,
		s.ProbeID,
		s.Amount,
		s.CLTVAggregator,
		s.Destination[:],
		s.ErrorPubKey,
		s.ErrorFlag,
		s.IsUpstream,
		s.PathLength,
	)
}

// MsgType returns the integer uniquely identifying this message type on the
// wire.
//
// This is part of the lnwire.Message interface.
func (s *DynamicInfoProbeMess) MsgType() MessageType {
	return MsgDynamicInfoProbeMess
}

// MaxPayloadLength returns the maximum allowed payload size for a
// GossipTimestampRange complete message observing the specified protocol
// version.
//
// This is part of the lnwire.Message interface.
func (s *DynamicInfoProbeMess) MaxPayloadLength(uint32) uint32 {

	//4 + 4 + 8 + 4 + 80 + 33 + 1 + 1 + 1
	return 140
}
