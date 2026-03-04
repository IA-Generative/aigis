package attestation

import (
    "context"
    "encoding/base64"
    "encoding/json"
    "errors"

    "go.uber.org/zap"
)

// AppleAttestation est la preuve envoyée par un device iOS (DeviceCheck / App Attest)
// Ref: https://developer.apple.com/documentation/devicecheck/establishing_your_app_s_integrity
type AppleAttestation struct {
    // Objet retourné par DCAppAttestService.attestKey()
    AttestationObjectB64 string `json:"attestation_object"`
    // Challenge serveur inclus dans le hash envoyé à Apple
    Challenge string `json:"challenge"`
    // KeyID retourné par generateKey()
    KeyID string `json:"key_id"`
}

// GoogleAttestation est la preuve envoyée par un device Android (Play Integrity)
// Ref: https://developer.android.com/google/play/integrity
type GoogleAttestation struct {
    // Token retourné par IntegrityManager.requestIntegrityToken()
    IntegrityToken string `json:"integrity_token"`
    // Nonce inclus dans la requête
    Nonce string `json:"nonce"`
}

// SecureEnclaveProvider vérifie les attestations Secure Enclave (iOS/Android).
// Le serveur valide la preuve auprès des APIs Apple/Google.
type SecureEnclaveProvider struct {
    appleTeamID    string
    appleBundleID  string
    googlePackage  string
    logger         *zap.Logger
}

func NewSecureEnclaveProvider() *SecureEnclaveProvider {
    return &SecureEnclaveProvider{
        logger: zap.NewNop(),
    }
}

func (p *SecureEnclaveProvider) Name() string {
    return "secure_enclave"
}

func (p *SecureEnclaveProvider) HardwareLevel() HardwareLevel {
    return HardwareLevelSecureEnclave
}

func (p *SecureEnclaveProvider) VerifyRegistration(_ context.Context, req *RegisterRequest) error {
    if req.HardwareProof == nil {
        return errors.New("secure enclave attestation requires a hardware proof")
    }

    proofBytes, err := base64.StdEncoding.DecodeString(*req.HardwareProof)
    if err != nil {
        return errors.New("invalid hardware proof encoding")
    }

    // Détecter iOS vs Android selon la structure JSON
    var raw map[string]interface{}
    if err := json.Unmarshal(proofBytes, &raw); err != nil {
        return errors.New("invalid proof format")
    }

    if _, isApple := raw["attestation_object"]; isApple {
        var proof AppleAttestation
        json.Unmarshal(proofBytes, &proof)
        return p.verifyAppleAttestation(proof, req.PublicKeyPEM)
    }

    if _, isGoogle := raw["integrity_token"]; isGoogle {
        var proof GoogleAttestation
        json.Unmarshal(proofBytes, &proof)
        return p.verifyGoogleAttestation(proof)
    }

    return errors.New("unknown attestation format")
}

func (p *SecureEnclaveProvider) VerifySignature(_ context.Context, publicKeyPEM, payload, signatureB64 string) error {
    // Comme pour TPM : une fois enregistré, les signatures de requête sont ECDSA standard
    // La sécurité vient du fait que la clé ne peut pas quitter le Secure Enclave
    sw := NewSoftwareProvider()
    return sw.VerifySignature(context.Background(), publicKeyPEM, payload, signatureB64)
}

// verifyAppleAttestation valide via l'API Apple App Attest
// Ref: https://developer.apple.com/documentation/devicecheck/validating_apps_that_connect_to_your_server
func (p *SecureEnclaveProvider) verifyAppleAttestation(proof AppleAttestation, publicKeyPEM string) error {
    // Étapes de validation Apple :
    // 1. Décoder l'attestation CBOR (format WebAuthn)
    // 2. Vérifier la signature avec la clé publique Apple WWDR CA
    // 3. Vérifier que le nonce = SHA256(challenge + publicKey)
    // 4. Vérifier aaguid = "appattestdevelop" ou "appattest" (prod)
    // 5. Vérifier que le certificat feuille correspond au KeyID

    // TODO : utiliser la lib https://github.com/fxamacker/cbor
    //        + certificat racine Apple : https://www.apple.com/certificateauthority/
    _ = proof
    _ = publicKeyPEM
    p.logger.Info("Apple App Attest verification (stub — implement with CBOR lib)")
    return nil
}

// verifyGoogleAttestation valide via l'API Google Play Integrity
func (p *SecureEnclaveProvider) verifyGoogleAttestation(proof GoogleAttestation) error {
    // Étapes de validation Google :
    // 1. Appeler https://playintegrity.googleapis.com/v1/{packageName}:decodeIntegrityToken
    // 2. Vérifier requestDetails.nonce == notre nonce
    // 3. Vérifier appIntegrity.appRecognitionVerdict == "PLAY_RECOGNIZED"
    // 4. Vérifier deviceIntegrity.deviceRecognitionVerdict contient "MEETS_STRONG_INTEGRITY"

    // TODO : appel HTTP vers Google Play Integrity API avec service account
    _ = proof
    p.logger.Info("Google Play Integrity verification (stub — implement with Play Integrity API)")
    return nil
}