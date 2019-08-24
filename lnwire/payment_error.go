package lnwire

import (
	"io"

	"github.com/btcsuite/btcd/btcec"
)

// PaymentError ..
type PaymentError struct {
	ProbeID     uint32
	Destination [EmbeddingSize]byte
	ErrorPubKey *btcec.PublicKey
	IsUpstream  uint8
	// Reason is an onion-encrypted blob that details why the HTLC was
	// failed. This blob is only fully decryptable by the initiator of the
	// HTLC message.
	Reason [260]byte
}

// A compile time check to ensure UpdateFailHTLC implements the lnwire.Message
// interface.
var _ Message = (*PaymentError)(nil)

// Decode deserializes a serialized DynamicInfoProbeMess message stored in the
// passed io.Reader
//
// This is part of the lnwire.Message interface.
func (s *PaymentError) Decode(r io.Reader, pver uint32) error {
	return ReadElements(r,
		&s.ProbeID,
		s.Destination[:],
		&s.ErrorPubKey,
		&s.IsUpstream,
		s.Reason[:],
	)
}

// Encode serializes the target SpanningTreeHello into the passed io.Writer
//
// This is part of the lnwire.Message interface.
func (s *PaymentError) Encode(w io.Writer, pver uint32) error {
	return WriteElements(w,
		s.ProbeID,
		s.Destination[:],
		s.ErrorPubKey,
		s.IsUpstream,
		s.Reason[:],
	)
}

// MsgType returns the integer uniquely identifying this message type on the
// wire.
//
// This is part of the lnwire.Message interface.
func (s *PaymentError) MsgType() MessageType {
	return MsgPaymentError
}

// MaxPayloadLength returns the maximum allowed payload size for a
// GossipTimestampRange complete message observing the specified protocol
// version.
//
// This is part of the lnwire.Message interface.
func (s *PaymentError) MaxPayloadLength(uint32) uint32 {

	var length uint32

	// Length of the probeid
	length += 4

	// Length of the destination
	length += 80

	// Length of the pubkey
	length += 33

	// length of IsUpstream
	length++
	// Length of the Reason
	length += 260

	return length
}
