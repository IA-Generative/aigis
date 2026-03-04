package attestation

import (
    "context"
    "errors"
)

// HardwareLevel décrit le niveau de protection de la clé privée
type HardwareLevel string

const (
    // HardwareLevelSoftware : clé en mémoire/filesystem, extractible
    HardwareLevelSoftware HardwareLevel = "software"

    // HardwareLevelTEE : Trusted Execution Environment (Android StrongBox, TPM)
    HardwareLevelTEE HardwareLevel = "tee"

    // HardwareLevelSecureEnclave : Secure Enclave Apple, non extractible
    HardwareLevelSecureEnclave HardwareLevel = "secure_enclave"
)

var (
    ErrHardwareNotSupported  = errors.New("hardware attestation not supported on this device")
    ErrHardwareRequired      = errors.New("hardware attestation required by server policy")
    ErrSoftwareDisallowed    = errors.New("software attestation disabled by server policy")
    ErrInvalidSignature      = errors.New("invalid device signature")
    ErrChallengeExpired      = errors.New("challenge expired")
    ErrReplayAttack          = errors.New("nonce already used")
    ErrTimestampOutOfWindow  = errors.New("timestamp out of allowed window")
)

// RegisterRequest est ce qu'un client envoie lors de l'enregistrement
type RegisterRequest struct {
    PublicKeyPEM  string        `json:"public_key"`
    KeyAlgorithm  string        `json:"key_algorithm"`  // "ES256"
    HardwareLevel HardwareLevel `json:"hardware_level"` // déclaré par le client
    // Preuve d'attestation hardware (si disponible)
    // Pour TPM : quote PCR signé
    // Pour Secure Enclave : attestation Apple/Google
    HardwareProof *string `json:"hardware_proof,omitempty"`
}

// Provider est l'interface implémentée par chaque backend d'attestation
type Provider interface {
    // Nom du provider pour les logs
    Name() string

    // HardwareLevel retourne le niveau de protection offert
    HardwareLevel() HardwareLevel

    // VerifyRegistration vérifie la preuve hardware à l'enregistrement (si applicable)
    // Pour software : no-op
    // Pour TPM/Enclave : vérifie la preuve constructeur
    VerifyRegistration(ctx context.Context, req *RegisterRequest) error

    // VerifySignature vérifie une signature ECDSA sur un payload
    VerifySignature(ctx context.Context, publicKeyPEM, payload, signatureB64 string) error
}

// Factory crée le bon provider selon le niveau déclaré et la politique serveur
func NewProvider(
    declared HardwareLevel,
    proof *string,
    mode string, // config.AttestationMode en string pour éviter le cycle d'import
) (Provider, error) {

    switch mode {

    case "software_only":
        // Politique stricte : on refuse tout ce qui n'est pas software
        if declared != HardwareLevelSoftware {
            return nil, ErrSoftwareDisallowed
        }
        return NewSoftwareProvider(), nil

    case "require_hardware":
        // Politique stricte : on refuse le software
        if declared == HardwareLevelSoftware {
            return nil, ErrHardwareRequired
        }
        return hardwareProvider(declared, proof)

    default: // "prefer_hardware"
        // Mode permissif : on accepte tout, on choisit le meilleur provider
        if declared == HardwareLevelSoftware {
            return NewSoftwareProvider(), nil
        }
        return hardwareProvider(declared, proof)
    }
}

func hardwareProvider(level HardwareLevel, proof *string) (Provider, error) {
    switch level {
    case HardwareLevelTEE:
        return NewTPMProvider(), nil
    case HardwareLevelSecureEnclave:
        return NewSecureEnclaveProvider(), nil
    default:
        return nil, ErrHardwareNotSupported
    }
}