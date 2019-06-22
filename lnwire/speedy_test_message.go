package lnwire

import "io"

//const embeddingSize = 80

// TestMessage ...
type TestMessage struct {
	TestID uint32
}

// NewTestMessage ...
func NewTestMessage(iD uint32) *TestMessage {
	return &TestMessage{TestID: iD}
}

// Decode deserializes a serialized SpanningTreeHello message stored in the
// passed io.Reader
//
// This is part of the lnwire.Message interface.
func (s *TestMessage) Decode(r io.Reader, pver uint32) error {
	return ReadElements(r,
		&s.TestID,
	)
}

// Encode serializes the target SpanningTreeHello into the passed io.Writer
//
// This is part of the lnwire.Message interface.
func (s *TestMessage) Encode(w io.Writer, pver uint32) error {
	return WriteElements(w,
		s.TestID,
	)
}

// MsgType returns the integer uniquely identifying this message type on the
// wire.
//
// This is part of the lnwire.Message interface.
func (s *TestMessage) MsgType() MessageType {
	return MsgTestMessage
}

// MaxPayloadLength returns the maximum allowed payload size for a
// GossipTimestampRange complete message observing the specified protocol
// version.
//
// This is part of the lnwire.Message interface.
func (s *TestMessage) MaxPayloadLength(uint32) uint32 {
	//4 + 80
	return 4
}
