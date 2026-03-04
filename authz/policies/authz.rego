package apisix.authz

import future.keywords

default allow = false
default deny_reason = "n/a"

# ─── Cas 1 : utilisateur direct avec device actif ──────────────────────────────
allow if {
    device_active
}

# ─── Cas 2 : device actif + signature vérifiée (device-bound session) ──────────
allow if {
    device_active
    device_signature_verified
}

# ─── Appel HTTP partagé : status du device ─────────────────────────────────────
device_response := response if {
    response := http.send({
        "method":  "GET",
        "url":     sprintf("%s/devices/%s/status", [opa.runtime().env.DEVICE_SERVICE_URL, input.device_id]),
        "headers": {"Accept": "application/json"},
        "cache":   true,
        "timeout": "2s",
    })
}

# ─── Appel HTTP : trust score du device ────────────────────────────────────────
trust_response := response if {
    response := http.send({
        "method":  "GET",
        "url":     sprintf("%s/devices/%s/trust", [opa.runtime().env.DEVICE_SERVICE_URL, input.device_id]),
        "headers": {"Accept": "application/json"},
        "cache":   true,
        "timeout": "2s",
    })
}

# ─── Appel HTTP : vérification signature X-Device-* ───────────────────────────
# Service B forward les headers dans input.device_headers
# OPA délègue la vérification crypto au device-service
verify_response := response if {
    input.device_headers.x_device_signature
    response := http.send({
        "method":  "POST",
        "url":     sprintf("%s/devices/%s/verify", [opa.runtime().env.DEVICE_SERVICE_URL, input.device_headers.x_device_id]),
        "headers": {
            "Accept":       "application/json",
            "Content-Type": "application/json",
        },
        "body": {
            "device_id": input.device_headers.x_device_id,
            "nonce":     input.device_headers.x_device_nonce,
            "timestamp": input.device_headers.x_device_timestamp,
            "signature": input.device_headers.x_device_signature,
        },
        "timeout": "2s",
    })
}

# ─── Règles device de base ─────────────────────────────────────────────────────
device_active if {
    device_response.status_code == 200
    device_response.body.status == "active"
    device_response.body.user_id == input.sub
}

# ─── Vérification signature device ────────────────────────────────────────────
device_signature_verified if {
    verify_response.status_code == 200
    verify_response.body.verified == true
}

# ─── Hardware level du device ──────────────────────────────────────────────────
device_hardware_level := device_response.body.hardware_level if {
    device_response.status_code == 200
}

device_trust_score := trust_response.body.trust_score if {
    trust_response.status_code == 200
}

# ─── Règles hardware-aware ─────────────────────────────────────────────────────

# Accès complet : device hardware (TPM/Enclave) + trust score >= 70 + signature vérifiée
allow_full_access if {
    device_active
    device_signature_verified
    device_hardware_level in {"tee", "secure_enclave"}
    device_trust_score >= 70
}

# Accès limité : device actif avec trust score >= 40
allow_limited_access if {
    device_active
    device_trust_score >= 40
}

# Accès sensible : nécessite hardware + trust score élevé + signature + attestation récente
allow_sensitive if {
    device_active
    device_signature_verified
    device_hardware_level in {"tee", "secure_enclave"}
    device_trust_score >= 70
    # Vérifier attestation récente (< 24h) via le champ dans la réponse status
    device_response.body.attested_at
}

# ─── Règles RBAC ──────────────────────────────────────────────────────────────
route_matches(perms) if {
    entry := perms[_]
    glob.match(entry.route, ["/"], input.route)
    entry.methods[_] == input.method
}

# ─── Raisons du refus (pour les logs d'audit) ─────────────────────────────────
deny_reason := "wrong_user_id" if {
    device_response.body.user_id != input.sub
}

deny_reason := "device_revoked" if {
    device_response.body.status == "revoked"
}

deny_reason := "device_suspended" if {
    device_response.body.status == "suspended"
}

deny_reason := "device_pending_approval" if {
    device_response.body.status == "pending_approval"
}

deny_reason := "device_signature_invalid" if {
    device_active
    input.device_headers.x_device_signature
    not device_signature_verified
}

deny_reason := "device_signature_missing" if {
    device_active
    not input.device_headers
    input.require_signature == true
}

deny_reason := "insufficient_hardware_level" if {
    device_active
    not device_hardware_level in {"tee", "secure_enclave"}
    input.require_hardware == true
}

deny_reason := "low_trust_score" if {
    device_active
    device_trust_score < 40
}

deny_reason := "trust_score_insufficient_for_sensitive" if {
    device_active
    device_trust_score < 70
    input.require_high_trust == true
}

# ─── Architecture A+B : Device management requires trust >= 70 ────────────
# Les actions de gestion de devices (approve, reject, revoke) nécessitent
# un score de confiance >= 70 sur le device émetteur.
allow_device_management if {
    device_active
    device_trust_score >= 70
}

deny_reason := "trust_insufficient_for_device_management" if {
    device_active
    device_trust_score < 70
    input.require_device_management == true
}

