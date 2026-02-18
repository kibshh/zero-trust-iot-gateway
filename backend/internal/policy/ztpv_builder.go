package policy

import (
	"encoding/binary"
	"errors"
)

// ZTPV (Zero Trust Policy for Verification) format constants
// Must match ESP32 ParsedPolicy constants in policy_types.h
const (
	ZTPVMagic         = uint32(0x5A545056) // "ZTPV" in little-endian
	ZTPVFormatVersion = uint32(1)
	ZTPVDeviceIDSize  = 16
	ZTPVRuleSize      = 6
	ZTPVMaxRules      = 64
	ZTPVMaxSigSize    = 72
	ZTPVSigLenSize    = 2                                    // uint16 little-endian
	ZTPVHeaderSize    = 4 + 4 + 4 + ZTPVDeviceIDSize + 4 + 2 // magic + format + policy_ver + device_id + expires + rule_count
)

// System states (must match ESP32 system_state::SystemState)
const (
	StateInit          = uint8(0)
	StateIdentityReady = uint8(1)
	StateAttested      = uint8(2)
	StateAuthorized    = uint8(3)
	StateOperational   = uint8(4)
	StateDegraded      = uint8(5)
	StateLocked        = uint8(6)
	StateRevoked       = uint8(7)
	StateAny           = uint8(0xFF)
)

// Policy actors (must match ESP32 policy::PolicyActor)
const (
	ActorSystem     = uint8(0)
	ActorBackend    = uint8(1)
	ActorLocalUser  = uint8(2)
	ActorPeripheral = uint8(3)
	ActorUnknown    = uint8(4)
	ActorAny        = uint8(0xFF)
)

// Policy actions (must match ESP32 policy::PolicyAction)
const (
	ActionGpioRead       = uint8(0)
	ActionGpioWrite      = uint8(1)
	ActionSensorRead     = uint8(2)
	ActionSensorConfig   = uint8(3)
	ActionActuatorWrite  = uint8(4)
	ActionI2cRead        = uint8(5)
	ActionI2cWrite       = uint8(6)
	ActionSpiRead        = uint8(7)
	ActionSpiWrite       = uint8(8)
	ActionUartRead       = uint8(9)
	ActionUartWrite      = uint8(10)
	ActionNetworkConnect = uint8(11)
	ActionNetworkSend    = uint8(12)
	ActionNetworkReceive = uint8(13)
	ActionStorageRead    = uint8(14)
	ActionStorageWrite   = uint8(15)
	ActionStorageErase   = uint8(16)
	ActionFirmwareUpdate = uint8(17)
	ActionSystemReboot   = uint8(18)
	ActionSystemSleep    = uint8(19)
	ActionConfigRead     = uint8(20)
	ActionConfigWrite    = uint8(21)
)

// Policy origins (must match ESP32 policy::PolicyOrigin)
const (
	OriginLocal   = uint8(0)
	OriginNetwork = uint8(1)
	OriginBus     = uint8(2)
	OriginStorage = uint8(3)
	OriginAny     = uint8(0xFF)
)

// Policy intents (must match ESP32 policy::PolicyIntent)
const (
	IntentNormalOperation = uint8(0)
	IntentProvisioning    = uint8(1)
	IntentRecovery        = uint8(2)
	IntentFirmwareUpdate  = uint8(3)
	IntentDiagnostics     = uint8(4)
	IntentAny             = uint8(0xFF)
)

// Policy decisions (must match ESP32 policy::PolicyDecision)
const (
	DecisionAllow = uint8(0)
	DecisionDeny  = uint8(1)
)

var (
	ErrZTPVInvalidDeviceID = errors.New("ztpv: invalid device ID length")
	ErrZTPVTooManyRules    = errors.New("ztpv: too many rules")
	ErrZTPVNoRules         = errors.New("ztpv: policy must have at least one rule")
	ErrZTPVSignatureFailed = errors.New("ztpv: failed to produce stable signature length")
)

// ZTPVRule represents a single policy rule
type ZTPVRule struct {
	State    uint8 // SystemState or 0xFF (any)
	Actor    uint8 // PolicyActor or 0xFF (any)
	Origin   uint8 // PolicyOrigin or 0xFF (any)
	Intent   uint8 // PolicyIntent or 0xFF (any)
	Action   uint8 // PolicyAction (exact value)
	Decision uint8 // PolicyDecision (Allow/Deny)
}

// ZTPVPolicy represents a runtime verification policy
type ZTPVPolicy struct {
	PolicyVersion uint32
	ExpiresAt     uint32 // Unix timestamp, 0 = no expiry
	Rules         []ZTPVRule
}

// ZTPVBuilder constructs ZTPV policy blobs
type ZTPVBuilder struct{}

func NewZTPVBuilder() *ZTPVBuilder {
	return &ZTPVBuilder{}
}

// Build creates a canonical ZTPV payload (without signature).
// Format (all multi-byte fields are little-endian):
//   - Magic: 4 bytes (0x5A545056)
//   - FormatVersion: 4 bytes
//   - PolicyVersion: 4 bytes
//   - DeviceID: 16 bytes
//   - ExpiresAt: 4 bytes (unix timestamp, 0 = no expiry)
//   - RuleCount: 2 bytes
//   - Rules: RuleCount × 6 bytes (state, actor, origin, intent, action, decision)
func (b *ZTPVBuilder) Build(p *ZTPVPolicy, deviceID []byte) ([]byte, error) {
	if len(deviceID) != ZTPVDeviceIDSize {
		return nil, ErrZTPVInvalidDeviceID
	}
	if len(p.Rules) == 0 {
		return nil, ErrZTPVNoRules
	}
	if len(p.Rules) > ZTPVMaxRules {
		return nil, ErrZTPVTooManyRules
	}

	size := ZTPVHeaderSize + len(p.Rules)*ZTPVRuleSize
	buf := make([]byte, size)
	offset := 0

	// Magic (LE)
	binary.LittleEndian.PutUint32(buf[offset:], ZTPVMagic)
	offset += 4

	// Format version (LE)
	binary.LittleEndian.PutUint32(buf[offset:], ZTPVFormatVersion)
	offset += 4

	// Policy version (LE)
	binary.LittleEndian.PutUint32(buf[offset:], p.PolicyVersion)
	offset += 4

	// Device ID (raw bytes)
	copy(buf[offset:], deviceID)
	offset += ZTPVDeviceIDSize

	// Expires at (LE)
	binary.LittleEndian.PutUint32(buf[offset:], p.ExpiresAt)
	offset += 4

	// Rule count (LE)
	binary.LittleEndian.PutUint16(buf[offset:], uint16(len(p.Rules)))
	offset += 2

	// Rules (6 bytes each: state, actor, origin, intent, action, decision)
	for _, rule := range p.Rules {
		buf[offset+0] = rule.State
		buf[offset+1] = rule.Actor
		buf[offset+2] = rule.Origin
		buf[offset+3] = rule.Intent
		buf[offset+4] = rule.Action
		buf[offset+5] = rule.Decision
		offset += ZTPVRuleSize
	}

	return buf, nil
}

// BuildSigned creates a complete ZTPV blob with embedded signature.
// Wire format: [payload][sig_len:2 LE][signature]
//
// The ESP32 verify_policy() hashes everything before the signature bytes,
// which includes the sig_len field. This requires knowing the signature
// length before computing the hash. ECDSA P-256 DER signatures are
// typically 70-72 bytes, so we use an iterative approach.
func (b *ZTPVBuilder) BuildSigned(p *ZTPVPolicy, deviceID []byte, signer *Signer) ([]byte, error) {
	payload, err := b.Build(p, deviceID)
	if err != nil {
		return nil, err
	}

	const maxRetries = 5
	assumedLen := uint16(ZTPVMaxSigSize)

	for i := 0; i < maxRetries; i++ {
		// Build data to sign: payload + sig_len
		signedData := make([]byte, len(payload)+ZTPVSigLenSize)
		copy(signedData, payload)
		binary.LittleEndian.PutUint16(signedData[len(payload):], assumedLen)

		sig, err := signer.Sign(signedData)
		if err != nil {
			return nil, err
		}

		if uint16(len(sig)) == assumedLen {
			// Lengths match - assemble final blob
			blob := make([]byte, len(signedData)+len(sig))
			copy(blob, signedData)
			copy(blob[len(signedData):], sig)
			return blob, nil
		}

		// Signature length didn't match assumption, retry with actual length
		assumedLen = uint16(len(sig))
	}

	return nil, ErrZTPVSignatureFailed
}

// DefaultRuntimeRules returns sensible default rules for an IoT device.
// These allow basic operation in Operational state and deny security-sensitive actions.
// TODO: Replace with configurable rule source (admin panel / config file)
func DefaultRuntimeRules() []ZTPVRule {
	return []ZTPVRule{
		// Operational state: allow sensor and actuator operations (system, local)
		{State: StateOperational, Actor: ActorSystem, Origin: OriginLocal, Intent: IntentNormalOperation, Action: ActionSensorRead, Decision: DecisionAllow},
		{State: StateOperational, Actor: ActorSystem, Origin: OriginLocal, Intent: IntentNormalOperation, Action: ActionSensorConfig, Decision: DecisionAllow},
		{State: StateOperational, Actor: ActorSystem, Origin: OriginLocal, Intent: IntentNormalOperation, Action: ActionActuatorWrite, Decision: DecisionAllow},
		{State: StateOperational, Actor: ActorSystem, Origin: OriginLocal, Intent: IntentNormalOperation, Action: ActionGpioRead, Decision: DecisionAllow},
		{State: StateOperational, Actor: ActorSystem, Origin: OriginLocal, Intent: IntentNormalOperation, Action: ActionGpioWrite, Decision: DecisionAllow},

		// Operational state: allow network communication
		{State: StateOperational, Actor: ActorSystem, Origin: OriginAny, Intent: IntentNormalOperation, Action: ActionNetworkConnect, Decision: DecisionAllow},
		{State: StateOperational, Actor: ActorSystem, Origin: OriginAny, Intent: IntentNormalOperation, Action: ActionNetworkSend, Decision: DecisionAllow},
		{State: StateOperational, Actor: ActorBackend, Origin: OriginNetwork, Intent: IntentNormalOperation, Action: ActionNetworkReceive, Decision: DecisionAllow},

		// Operational state: allow peripheral bus communication
		{State: StateOperational, Actor: ActorSystem, Origin: OriginBus, Intent: IntentNormalOperation, Action: ActionI2cRead, Decision: DecisionAllow},
		{State: StateOperational, Actor: ActorSystem, Origin: OriginBus, Intent: IntentNormalOperation, Action: ActionI2cWrite, Decision: DecisionAllow},
		{State: StateOperational, Actor: ActorSystem, Origin: OriginBus, Intent: IntentNormalOperation, Action: ActionSpiRead, Decision: DecisionAllow},
		{State: StateOperational, Actor: ActorSystem, Origin: OriginBus, Intent: IntentNormalOperation, Action: ActionSpiWrite, Decision: DecisionAllow},
		{State: StateOperational, Actor: ActorSystem, Origin: OriginBus, Intent: IntentNormalOperation, Action: ActionUartRead, Decision: DecisionAllow},
		{State: StateOperational, Actor: ActorSystem, Origin: OriginBus, Intent: IntentNormalOperation, Action: ActionUartWrite, Decision: DecisionAllow},

		// Operational state: allow storage read (configuration, calibration)
		{State: StateOperational, Actor: ActorSystem, Origin: OriginLocal, Intent: IntentNormalOperation, Action: ActionStorageRead, Decision: DecisionAllow},
		{State: StateOperational, Actor: ActorSystem, Origin: OriginLocal, Intent: IntentNormalOperation, Action: ActionConfigRead, Decision: DecisionAllow},

		// Firmware update: only backend can trigger, only with explicit intent
		{State: StateOperational, Actor: ActorBackend, Origin: OriginNetwork, Intent: IntentFirmwareUpdate, Action: ActionFirmwareUpdate, Decision: DecisionAllow},

		// Deny security-sensitive operations by default (catch-all)
		{State: StateAny, Actor: ActorAny, Origin: OriginAny, Intent: IntentAny, Action: ActionFirmwareUpdate, Decision: DecisionDeny},
		{State: StateAny, Actor: ActorAny, Origin: OriginAny, Intent: IntentAny, Action: ActionConfigWrite, Decision: DecisionDeny},
		{State: StateAny, Actor: ActorAny, Origin: OriginAny, Intent: IntentAny, Action: ActionStorageErase, Decision: DecisionDeny},
	}
}
