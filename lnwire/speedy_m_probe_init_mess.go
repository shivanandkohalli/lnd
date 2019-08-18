package lnwire

import (
	"io"

	"github.com/btcsuite/btcd/btcec"
)

// ProbeInitMess This message is sent by a sender node to the destination
// node during generation of invoice. It is a part of error returning
// scheme in speedymurmurs
type ProbeInitMess struct {
	ProbeID    uint32
	NodePubKey *btcec.PublicKey
	ErrorKey1  *btcec.PublicKey
	ErrorKey2  *btcec.PublicKey
}

// A compile time check to ensure ProbeInitMess implements the lnwire.Message
// interface.
var _ Message = (*ProbeInitMess)(nil)

// Encode serializes the target ProbeInitMess into the passed io.Writer
// implementation. Serialization will observe the rules defined by the passed
// protocol version.
//
// This is part of the lnwire.Message interface.
func (p *ProbeInitMess) Encode(w io.Writer, pver uint32) error {
	return WriteElements(w,
		p.ProbeID,
		p.NodePubKey,
		p.ErrorKey1,
		p.ErrorKey2,
	)
}

// Decode deserializes the serialized ProbeInitMess stored in the passed
// io.Reader into the target ProbeInitMess using the deserialization rules
// defined by the passed protocol version.
//
// This is part of the lnwire.Message interface.
func (p *ProbeInitMess) Decode(r io.Reader, pver uint32) error {
	return ReadElements(r,
		&p.ProbeID,
		&p.NodePubKey,
		&p.ErrorKey1,
		&p.ErrorKey2,
	)
}

// MsgType returns the MessageType code which uniquely identifies this message
// as an AcceptChannel on the wire.
//
// This is part of the lnwire.Message interface.
func (p *ProbeInitMess) MsgType() MessageType {
	return MsgProbeInitMess
}

// MaxPayloadLength returns the maximum allowed payload length for a
// AcceptChannel message.
// This is part of the lnwire.Message interface.
func (p *ProbeInitMess) MaxPayloadLength(uint32) uint32 {
	// 4 + (33*3)
	return 103
}
