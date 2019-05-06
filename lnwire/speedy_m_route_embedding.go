package lnwire

import "io"

//const embeddingSize = 80

// PrefixEmbedding ...
type PrefixEmbedding struct {
	NodeID    uint32
	Embedding [EmbeddingSize]byte
}

// NewPrefixEmbedding ...
func NewPrefixEmbedding(nodeID uint32, emb []byte) *PrefixEmbedding {
	var temp PrefixEmbedding
	temp.NodeID = nodeID
	copy(temp.Embedding[:], emb)
	return &temp
}

// Decode deserializes a serialized SpanningTreeHello message stored in the
// passed io.Reader
//
// This is part of the lnwire.Message interface.
func (s *PrefixEmbedding) Decode(r io.Reader, pver uint32) error {
	return ReadElements(r,
		&s.NodeID, s.Embedding[:],
	)
}

// Encode serializes the target SpanningTreeHello into the passed io.Writer
//
// This is part of the lnwire.Message interface.
func (s *PrefixEmbedding) Encode(w io.Writer, pver uint32) error {
	return WriteElements(w,
		s.NodeID, s.Embedding[:],
	)
}

// MsgType returns the integer uniquely identifying this message type on the
// wire.
//
// This is part of the lnwire.Message interface.
func (s *PrefixEmbedding) MsgType() MessageType {
	return MsgSpeedyPrefixEmbedding
}

// MaxPayloadLength returns the maximum allowed payload size for a
// GossipTimestampRange complete message observing the specified protocol
// version.
//
// This is part of the lnwire.Message interface.
func (s *PrefixEmbedding) MaxPayloadLength(uint32) uint32 {
	//4 + 80
	return 84
}
