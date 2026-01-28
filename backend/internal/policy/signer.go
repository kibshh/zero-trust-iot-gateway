package policy

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"errors"
)

var (
	ErrNoPrivateKey    = errors.New("no private key configured")
	ErrInvalidKey      = errors.New("invalid key type, expected ECDSA P-256")
	ErrSignatureFailed = errors.New("signature generation failed")
)

// Signer signs policy payloads using ECDSA P-256
type Signer struct {
	privateKey *ecdsa.PrivateKey
	publicKey  *ecdsa.PublicKey
}

// NewSigner creates a signer with the given ECDSA P-256 private key (DER encoded)
func NewSigner(privateKeyDER []byte) (*Signer, error) {
	key, err := x509.ParseECPrivateKey(privateKeyDER)
	if err != nil {
		return nil, err
	}

	return &Signer{
		privateKey: key,
		publicKey:  &key.PublicKey,
	}, nil
}

// NewSignerFromKey creates a signer from an existing ECDSA private key
func NewSignerFromKey(key *ecdsa.PrivateKey) (*Signer, error) {
	if key == nil {
		return nil, ErrNoPrivateKey
	}

	return &Signer{
		privateKey: key,
		publicKey:  &key.PublicKey,
	}, nil
}

// Sign creates an ECDSA P-256 signature over the payload
// Returns DER-encoded signature
func (s *Signer) Sign(payload []byte) ([]byte, error) {
	if s.privateKey == nil {
		return nil, ErrNoPrivateKey
	}

	hash := sha256.Sum256(payload)
	signature, err := ecdsa.SignASN1(rand.Reader, s.privateKey, hash[:])
	if err != nil {
		return nil, ErrSignatureFailed
	}

	return signature, nil
}

// SignPolicy builds and signs a policy, returning a SignedPolicy
func (s *Signer) SignPolicy(p *Policy, deviceID []byte) (*SignedPolicy, error) {
	builder := NewBuilder()

	payload, err := builder.Build(p, deviceID)
	if err != nil {
		return nil, err
	}

	signature, err := s.Sign(payload)
	if err != nil {
		return nil, err
	}

	return &SignedPolicy{
		Payload:   payload,
		Signature: signature,
	}, nil
}

// PublicKeyDER returns the DER-encoded public key (SPKI format)
func (s *Signer) PublicKeyDER() ([]byte, error) {
	return x509.MarshalPKIXPublicKey(s.publicKey)
}

// Verifier verifies policy signatures
type Verifier struct {
	publicKey *ecdsa.PublicKey
}

// NewVerifier creates a verifier from a DER-encoded public key (SPKI format)
func NewVerifier(publicKeyDER []byte) (*Verifier, error) {
	pub, err := x509.ParsePKIXPublicKey(publicKeyDER)
	if err != nil {
		return nil, err
	}

	ecdsaPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, ErrInvalidKey
	}

	return &Verifier{publicKey: ecdsaPub}, nil
}

// Verify checks the signature over the payload
func (v *Verifier) Verify(payload, signatureDER []byte) bool {
	hash := sha256.Sum256(payload)
	return ecdsa.VerifyASN1(v.publicKey, hash[:], signatureDER)
}

// VerifySignedPolicy verifies a complete signed policy
func (v *Verifier) VerifySignedPolicy(sp *SignedPolicy) bool {
	if sp == nil || len(sp.Payload) == 0 || len(sp.Signature) == 0 {
		return false
	}
	return v.Verify(sp.Payload, sp.Signature)
}

