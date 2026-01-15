package attestation

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"math/big"
)

// ecdsaSignature represents the ASN.1 structure of an ECDSA signature
type ecdsaSignature struct {
	R *big.Int
	S *big.Int
}

// VerifyECDSAP256 verifies an ECDSA P-256 signature over a message.
// pubKeyDER must be a DER-encoded SubjectPublicKeyInfo (SPKI) format public key.
// signatureDER must be DER-encoded ASN.1 as SEQUENCE { r INTEGER, s INTEGER }.
func VerifyECDSAP256(
	pubKeyDER []byte,
	message []byte,
	signatureDER []byte,
) bool {
	pub, err := x509.ParsePKIXPublicKey(pubKeyDER)
	if err != nil {
		return false
	}
	// Check if the public key is a valid ECDSA P-256 public key
	ecdsaPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return false
	}

	if ecdsaPub.Curve != elliptic.P256() {
		return false
	}

	hash := sha256.Sum256(message)

	var sig ecdsaSignature
	if _, err := asn1.Unmarshal(signatureDER, &sig); err != nil {
		return false
	}

	if sig.R == nil || sig.S == nil {
		return false
	}

	return ecdsa.Verify(ecdsaPub, hash[:], sig.R, sig.S)
}

