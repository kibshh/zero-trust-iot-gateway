package policy

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"time"
)

// Canonical policy format constants
const (
	MagicBytes       = "ZTPL" // Zero Trust PoLicy
	FormatVersion    = 1
	DeviceIDSize     = 16
	FirmwareHashSize = 32
	MaxHashes        = 16
	HeaderSize       = 4 + 1 + 1 // magic + version + flags
	TimestampSize    = 8
	VersionFieldSize = 8
	HashCountSize    = 1
	// Signed blob wire format: [payload_len:2][payload][sig_len:2][signature]
	LengthFieldSize = 2 // uint16 little-endian
)

var (
	ErrInvalidDeviceID = errors.New("invalid device ID length")
	ErrTooManyHashes   = errors.New("too many firmware hashes")
	ErrInvalidHash     = errors.New("invalid firmware hash length")
)

// SignedPolicy represents a policy with its signature
type SignedPolicy struct {
	Payload   []byte // Canonical binary payload (without signature)
	Signature []byte // ECDSA P-256 DER signature
}

// Pack serializes a SignedPolicy into wire format:
// [payload_len:2 LE][payload][sig_len:2 LE][signature]
func (sp *SignedPolicy) Pack() []byte {
	totalLen := LengthFieldSize + len(sp.Payload) + LengthFieldSize + len(sp.Signature)
	buf := make([]byte, totalLen)
	offset := 0

	// Payload length (little-endian)
	binary.LittleEndian.PutUint16(buf[offset:], uint16(len(sp.Payload)))
	offset += LengthFieldSize

	// Payload
	copy(buf[offset:], sp.Payload)
	offset += len(sp.Payload)

	// Signature length (little-endian)
	binary.LittleEndian.PutUint16(buf[offset:], uint16(len(sp.Signature)))
	offset += LengthFieldSize

	// Signature
	copy(buf[offset:], sp.Signature)

	return buf
}

// UnpackSignedBlob deserializes wire format into a SignedPolicy
func UnpackSignedBlob(blob []byte) (*SignedPolicy, error) {
	if len(blob) < LengthFieldSize*2 {
		return nil, errors.New("blob too short")
	}

	offset := 0

	// Payload length
	payloadLen := int(binary.LittleEndian.Uint16(blob[offset:]))
	offset += LengthFieldSize

	if len(blob) < offset+payloadLen+LengthFieldSize {
		return nil, errors.New("blob too short for payload")
	}

	// Payload
	payload := make([]byte, payloadLen)
	copy(payload, blob[offset:offset+payloadLen])
	offset += payloadLen

	// Signature length
	sigLen := int(binary.LittleEndian.Uint16(blob[offset:]))
	offset += LengthFieldSize

	if len(blob) != offset+sigLen {
		return nil, errors.New("blob size mismatch")
	}

	// Signature
	signature := make([]byte, sigLen)
	copy(signature, blob[offset:offset+sigLen])

	return &SignedPolicy{
		Payload:   payload,
		Signature: signature,
	}, nil
}

// Builder constructs canonical policy payloads
type Builder struct{}

func NewBuilder() *Builder {
	return &Builder{}
}

// Build creates a canonical binary representation of a policy.
// Format:
//   - Magic: 4 bytes "ZTPL"
//   - Version: 1 byte
//   - Flags: 1 byte (reserved)
//   - DeviceID: 16 bytes
//   - MinFirmwareVersion: 8 bytes (big-endian)
//   - IssuedAt: 8 bytes (unix timestamp, big-endian)
//   - ExpiresAt: 8 bytes (unix timestamp, big-endian)
//   - HashCount: 2 bytes (big-endian)
//   - AllowedHashes: HashCount * 32 bytes
func (b *Builder) Build(p *Policy, deviceID []byte) ([]byte, error) {
	if len(deviceID) != DeviceIDSize {
		return nil, ErrInvalidDeviceID
	}

	if len(p.AllowedHashes) > MaxHashes {
		return nil, ErrTooManyHashes
	}

	for _, h := range p.AllowedHashes {
		if len(h) != FirmwareHashSize {
			return nil, ErrInvalidHash
		}
	}

	// Calculate total size
	size := HeaderSize + DeviceIDSize + VersionFieldSize + TimestampSize*2 + HashCountSize + len(p.AllowedHashes)*FirmwareHashSize

	buf := make([]byte, size)
	offset := 0

	// Magic
	copy(buf[offset:], MagicBytes)
	offset += len(MagicBytes)

	// Version
	buf[offset] = FormatVersion
	offset++

	// Flags (reserved)
	buf[offset] = 0
	offset++

	// DeviceID
	copy(buf[offset:], deviceID)
	offset += DeviceIDSize

	// MinFirmwareVersion
	binary.BigEndian.PutUint64(buf[offset:], p.MinFirmwareVersion)
	offset += VersionFieldSize

	// IssuedAt
	binary.BigEndian.PutUint64(buf[offset:], uint64(p.IssuedAt.Unix()))
	offset += TimestampSize

	// ExpiresAt
	binary.BigEndian.PutUint64(buf[offset:], uint64(p.ExpiresAt.Unix()))
	offset += TimestampSize

	// HashCount
	buf[offset] = uint8(len(p.AllowedHashes))
	offset += HashCountSize

	// AllowedHashes
	for _, h := range p.AllowedHashes {
		copy(buf[offset:], h)
		offset += FirmwareHashSize
	}

	return buf, nil
}

// Parse decodes a canonical policy payload back into a Policy struct
func (b *Builder) Parse(data []byte) (*Policy, []byte, error) {
	if len(data) < HeaderSize+DeviceIDSize+VersionFieldSize+TimestampSize*2+HashCountSize {
		return nil, nil, errors.New("payload too short")
	}

	offset := 0

	// Verify magic
	if string(data[offset:offset+len(MagicBytes)]) != MagicBytes {
		return nil, nil, errors.New("invalid magic bytes")
	}
	offset += len(MagicBytes)

	// Verify version
	if data[offset] != FormatVersion {
		return nil, nil, errors.New("unsupported format version")
	}
	offset++

	// Skip flags for now
	offset++

	// DeviceID
	deviceID := make([]byte, DeviceIDSize)
	copy(deviceID, data[offset:offset+DeviceIDSize])
	offset += DeviceIDSize

	// MinFirmwareVersion
	minVersion := binary.BigEndian.Uint64(data[offset:])
	offset += VersionFieldSize

	// IssuedAt
	issuedAt := time.Unix(int64(binary.BigEndian.Uint64(data[offset:])), 0)
	offset += TimestampSize

	// ExpiresAt
	expiresAt := time.Unix(int64(binary.BigEndian.Uint64(data[offset:])), 0)
	offset += TimestampSize

	// HashCount
	hashCount := data[offset]
	offset += HashCountSize

	if int(hashCount) > MaxHashes {
		return nil, nil, ErrTooManyHashes
	}

	expectedLen := offset + int(hashCount)*FirmwareHashSize
	if len(data) < expectedLen {
		return nil, nil, errors.New("payload too short for hash count")
	}

	// AllowedHashes
	hashes := make([][]byte, hashCount)
	for i := range hashes {
		hashes[i] = make([]byte, FirmwareHashSize)
		copy(hashes[i], data[offset:offset+FirmwareHashSize])
		offset += FirmwareHashSize
	}

	p := &Policy{
		DeviceID:           hex.EncodeToString(deviceID),
		MinFirmwareVersion: minVersion,
		IssuedAt:           issuedAt,
		ExpiresAt:          expiresAt,
		AllowedHashes:      hashes,
		Revoked:            false, // Runtime state, not from payload
	}

	return p, deviceID, nil
}

