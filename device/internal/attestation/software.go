package attestation

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"math/big"
)

// SoftwareProvider implémente l'attestation ECDSA pure logiciel.
// La clé privée vit sur le filesystem du client — extractible si compromis.
type SoftwareProvider struct{}

func NewSoftwareProvider() *SoftwareProvider {
	return &SoftwareProvider{}
}

func (p *SoftwareProvider) Name() string {
	return "software"
}

func (p *SoftwareProvider) HardwareLevel() HardwareLevel {
	return HardwareLevelSoftware
}

// VerifyRegistration : rien à vérifier pour le software
func (p *SoftwareProvider) VerifyRegistration(_ context.Context, req *RegisterRequest) error {
	// On vérifie juste que la clé publique est valide
	_, err := parseECDSAPublicKey(req.PublicKeyPEM)
	return err
}

func (p *SoftwareProvider) VerifySignature(_ context.Context, publicKeyPEM, payload, signatureB64 string) error {
	pubKey, err := parseECDSAPublicKey(publicKeyPEM)
	if err != nil {
		return err
	}

	sigBytes, err := base64.StdEncoding.DecodeString(signatureB64)
	if err != nil {
		return ErrInvalidSignature
	}

	hash := sha256.Sum256([]byte(payload))

	// Try ASN.1 DER format first (standard Go / OpenSSL signatures)
	if ecdsa.VerifyASN1(pubKey, hash[:], sigBytes) {
		return nil
	}

	// Try IEEE P1363 / raw (r || s) format — Web Crypto API uses this
	keySize := (pubKey.Curve.Params().BitSize + 7) / 8
	if len(sigBytes) == 2*keySize {
		r := new(big.Int).SetBytes(sigBytes[:keySize])
		s := new(big.Int).SetBytes(sigBytes[keySize:])
		if ecdsa.Verify(pubKey, hash[:], r, s) {
			return nil
		}
	}

	return ErrInvalidSignature
}

// parseECDSAPublicKey est partagée par tous les providers
func parseECDSAPublicKey(pubPEM string) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pubPEM))
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	key, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("not an ECDSA public key")
	}

	return key, nil
}
