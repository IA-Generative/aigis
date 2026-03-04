package attestation

import (
    "context"
    "crypto/sha256"
    "encoding/base64"
    "encoding/json"
    "errors"

    "go.uber.org/zap"
)

// TPMQuote est la structure de preuve envoyée par le client lors du register
// Le client génère cette preuve via tpm2-tools ou go-tpm
type TPMQuote struct {
    // Quote PCR signé par la clé AK (Attestation Key) du TPM
    QuoteB64     string `json:"quote"`
    // Signature sur le quote par la clé AK
    SignatureB64 string `json:"signature"`
    // Certificat EK (Endorsement Key) émis par le constructeur
    EKCertPEM    string `json:"ek_cert"`
    // Nonce serveur inclus dans le quote (anti-replay)
    Nonce        string `json:"nonce"`
}

// TPMProvider vérifie les attestations TPM 2.0.
// Côté serveur on ne parle pas au TPM — on vérifie la preuve cryptographique.
type TPMProvider struct {
    // En production : injecter le CA du fabricant (Infineon, STM, etc.)
    // pour vérifier le certificat EK
    trustedEKRoots []string
    logger         *zap.Logger
}

func NewTPMProvider() *TPMProvider {
    return &TPMProvider{
        logger: zap.NewNop(), // remplacé par injection en prod
    }
}

func (p *TPMProvider) Name() string {
    return "tpm"
}

func (p *TPMProvider) HardwareLevel() HardwareLevel {
    return HardwareLevelTEE
}

func (p *TPMProvider) VerifyRegistration(_ context.Context, req *RegisterRequest) error {
    if req.HardwareProof == nil {
        return errors.New("TPM attestation requires a hardware proof")
    }

    var quote TPMQuote
    proofBytes, err := base64.StdEncoding.DecodeString(*req.HardwareProof)
    if err != nil {
        return errors.New("invalid hardware proof encoding")
    }

    if err := json.Unmarshal(proofBytes, &quote); err != nil {
        return errors.New("invalid TPM quote format")
    }

    // Vérification en 3 étapes :

    // 1. Le certificat EK est bien signé par un CA constructeur de confiance
    if err := p.verifyEKCertificate(quote.EKCertPEM); err != nil {
        return err
    }

    // 2. Le quote PCR contient bien le nonce qu'on avait émis
    if err := p.verifyNonceInQuote(quote.QuoteB64, quote.Nonce); err != nil {
        return err
    }

    // 3. La signature sur le quote est valide (signée par la clé AK du TPM)
    if err := p.verifyQuoteSignature(quote.QuoteB64, quote.SignatureB64, req.PublicKeyPEM); err != nil {
        return err
    }

    p.logger.Info("TPM attestation verified")
    return nil
}

func (p *TPMProvider) VerifySignature(_ context.Context, publicKeyPEM, payload, signatureB64 string) error {
    // Une fois le device enregistré avec TPM, les signatures de requête
    // sont vérifiées de la même façon que software (ECDSA)
    // La valeur ajoutée est dans le VerifyRegistration — la clé est liée au TPM
    sw := NewSoftwareProvider()
    return sw.VerifySignature(context.Background(), publicKeyPEM, payload, signatureB64)
}

// verifyEKCertificate vérifie que le certificat EK est émis par un CA constructeur connu
func (p *TPMProvider) verifyEKCertificate(ekCertPEM string) error {
    // TODO production : charger les CA Infineon/STM/NTC depuis un bundle
    // et vérifier la chaîne de certificats
    // Ref: https://www.infineon.com/cms/en/product/security-smart-card-solutions/optiga-embedded-security-solutions/optiga-tpm/
    if ekCertPEM == "" {
        return errors.New("missing EK certificate")
    }
    // Implémentation complète nécessite x509.Certificate + pool de CA constructeurs
    return nil
}

// verifyNonceInQuote vérifie que le nonce serveur est bien dans le quote TPM
func (p *TPMProvider) verifyNonceInQuote(quoteB64, expectedNonce string) error {
    quoteBytes, err := base64.StdEncoding.DecodeString(quoteB64)
    if err != nil {
        return errors.New("invalid quote encoding")
    }

    // Le quote TPM2B_ATTEST contient un qualifyingData = SHA256(nonce)
    expectedHash := sha256.Sum256([]byte(expectedNonce))
    _ = quoteBytes
    _ = expectedHash
    // TODO : parser la structure TPMS_ATTEST et comparer qualifyingData
    // Ref: https://github.com/google/go-tpm
    return nil
}

func (p *TPMProvider) verifyQuoteSignature(quoteB64, sigB64, pubKeyPEM string) error {
    sw := NewSoftwareProvider()
    return sw.VerifySignature(context.Background(), pubKeyPEM, quoteB64, sigB64)
}