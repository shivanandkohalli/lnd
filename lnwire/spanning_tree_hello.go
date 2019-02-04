package lnwire

import "io"

// SpanningTreeHello comprises of the elements of a Hello Message in a spanning tree construction
// This struct implements the lnwire.Message interface
type SpanningTreeHello struct {
	NodeID     uint32
	RootNodeID uint32
	CostToRoot uint32
}

// NewSpanningTreeHello creates new instance of the hello message object
func NewSpanningTreeHello(nodeID uint32, rootNodeID uint32, costToRoot uint32) *SpanningTreeHello {
	return &SpanningTreeHello{
		NodeID:     nodeID,
		RootNodeID: rootNodeID,
		CostToRoot: costToRoot,
	}
}

// Decode deserializes a serialized SpanningTreeHello message stored in the
// passed io.Reader
//
// This is part of the lnwire.Message interface.
func (s *SpanningTreeHello) Decode(r io.Reader, pver uint32) error {
	return ReadElements(r,
		&s.NodeID, &s.RootNodeID, &s.CostToRoot,
	)
}

// Encode serializes the target SpanningTreeHello into the passed io.Writer
//
// This is part of the lnwire.Message interface.
func (s *SpanningTreeHello) Encode(w io.Writer, pver uint32) error {
	return WriteElements(w,
		s.NodeID, s.RootNodeID, s.CostToRoot,
	)
}

// MsgType returns the integer uniquely identifying this message type on the
// wire.
//
// This is part of the lnwire.Message interface.
func (s *SpanningTreeHello) MsgType() MessageType {
	return MsgSpanningTreeHello
}

// MaxPayloadLength returns the maximum allowed payload size for a
// GossipTimestampRange complete message observing the specified protocol
// version.
//
// This is part of the lnwire.Message interface.
func (s *SpanningTreeHello) MaxPayloadLength(uint32) uint32 {
	//4 + 4 + 4
	return 12
}
