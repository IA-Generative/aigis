package apisix.authz

import future.keywords

# ─── Fixtures ──────────────────────────────────────────────────────────────────
mock_device_active        := {"status": "active",  "user_id": "bob-uuid", "hardware_level": "tee", "trust_score": 85, "attested_at": "2026-03-05T10:00:00Z"}
mock_device_active_sw     := {"status": "active",  "user_id": "bob-uuid", "hardware_level": "software", "trust_score": 30}
mock_device_active_medium := {"status": "active",  "user_id": "bob-uuid", "hardware_level": "software", "trust_score": 50}
mock_device_revoked       := {"status": "revoked", "user_id": "bob-uuid", "hardware_level": "tee", "trust_score": 0}
mock_device_suspended     := {"status": "suspended", "user_id": "bob-uuid", "hardware_level": "tee", "trust_score": 40}

mock_trust_high    := {"trust_score": 85, "hardware_level": "tee"}
mock_trust_medium  := {"trust_score": 50, "hardware_level": "software"}
mock_trust_low     := {"trust_score": 20, "hardware_level": "software"}

mock_verify_ok     := {"verified": true, "device_id": "dev-abc", "trust_score": 85}
mock_verify_fail   := {"error": "invalid device signature"}

mock_permissions := {
    "roles": ["user"],
    "permissions": {
        "user": [
            {"route": "/api/v1/orders/*", "methods": ["GET", "POST"]},
            {"route": "/api/v1/profile",  "methods": ["GET"]},
        ]
    }
}

mock_device_headers := {
    "x_device_id":        "dev-abc",
    "x_device_nonce":     "nonce-123",
    "x_device_timestamp": "2026-03-05T12:00:00Z",
    "x_device_signature": "dGVzdC1zaWduYXR1cmU=",
}

# Dispatches by URL: device-status calls → active device, trust calls → trust, verify calls → verify
mock_http_send_active(req) := {"status_code": 200, "body": mock_device_active} if {
    contains(req.url, "/status")
}
mock_http_send_active(req) := {"status_code": 200, "body": mock_trust_high} if {
    contains(req.url, "/trust")
}
mock_http_send_active(req) := {"status_code": 200, "body": mock_verify_ok} if {
    contains(req.url, "/verify")
}
mock_http_send_active(req) := {"status_code": 200, "body": mock_permissions} if {
    contains(req.url, "/permissions")
}

mock_http_send_active_verify_fail(req) := {"status_code": 200, "body": mock_device_active} if {
    contains(req.url, "/status")
}
mock_http_send_active_verify_fail(req) := {"status_code": 200, "body": mock_trust_high} if {
    contains(req.url, "/trust")
}
mock_http_send_active_verify_fail(req) := {"status_code": 401, "body": mock_verify_fail} if {
    contains(req.url, "/verify")
}

mock_http_send_software(req) := {"status_code": 200, "body": mock_device_active_sw} if {
    contains(req.url, "/status")
}
mock_http_send_software(req) := {"status_code": 200, "body": mock_trust_low} if {
    contains(req.url, "/trust")
}
mock_http_send_software(req) := {"status_code": 200, "body": mock_verify_ok} if {
    contains(req.url, "/verify")
}

mock_http_send_medium(req) := {"status_code": 200, "body": mock_device_active_medium} if {
    contains(req.url, "/status")
}
mock_http_send_medium(req) := {"status_code": 200, "body": mock_trust_medium} if {
    contains(req.url, "/trust")
}
mock_http_send_medium(req) := {"status_code": 200, "body": mock_verify_ok} if {
    contains(req.url, "/verify")
}

mock_http_send_revoked(_) := {"status_code": 200, "body": mock_device_revoked}

mock_http_send_suspended(req) := {"status_code": 200, "body": mock_device_suspended} if {
    contains(req.url, "/status")
}
mock_http_send_suspended(req) := {"status_code": 200, "body": mock_trust_medium} if {
    contains(req.url, "/trust")
}

mock_runtime := {"env": {
    "DEVICE_SERVICE_URL":      "http://device-service:8080",
    "PERMISSIONS_SERVICE_URL": "http://permissions-service:8080",
}}

# ─── Test : accès autorisé (hardware + high trust) ────────────────────────────
test_allow_active_device_with_permission if {
    allow with input as {
        "sub":       "bob-uuid",
        "device_id": "dev-abc",
        "route":     "/api/v1/orders/123",
        "method":    "GET",
    }
    with http.send as mock_http_send_active
    with opa.runtime as mock_runtime
}

# ─── Test : accès complet avec signature vérifiée ─────────────────────────────
test_allow_full_access_hardware_with_signature if {
    allow_full_access with input as {
        "sub":            "bob-uuid",
        "device_id":      "dev-abc",
        "device_headers": mock_device_headers,
    }
    with http.send as mock_http_send_active
    with opa.runtime as mock_runtime
}

# ─── Test : full access refusé sans signature ─────────────────────────────────
test_deny_full_access_without_signature if {
    not allow_full_access with input as {
        "sub":       "bob-uuid",
        "device_id": "dev-abc",
    }
    with http.send as mock_http_send_active
    with opa.runtime as mock_runtime
}

# ─── Test : full access refusé si signature invalide ──────────────────────────
test_deny_full_access_bad_signature if {
    not allow_full_access with input as {
        "sub":            "bob-uuid",
        "device_id":      "dev-abc",
        "device_headers": mock_device_headers,
    }
    with http.send as mock_http_send_active_verify_fail
    with opa.runtime as mock_runtime
}

# ─── Test : accès limité (software + medium trust, pas de signature requise) ──
test_allow_limited_access_medium_trust if {
    allow_limited_access with input as {
        "sub":       "bob-uuid",
        "device_id": "dev-abc",
    }
    with http.send as mock_http_send_medium
    with opa.runtime as mock_runtime
}

# ─── Test : accès refusé (software + low trust = basic allow still works) ─────
test_allow_basic_access_software if {
    allow with input as {
        "sub":       "bob-uuid",
        "device_id": "dev-software",
    }
    with http.send as mock_http_send_software
    with opa.runtime as mock_runtime
}

# ─── Test : full access refusé pour software ──────────────────────────────────
test_deny_full_access_software if {
    not allow_full_access with input as {
        "sub":            "bob-uuid",
        "device_id":      "dev-software",
        "device_headers": mock_device_headers,
    }
    with http.send as mock_http_send_software
    with opa.runtime as mock_runtime
}

# ─── Test : device révoqué → refus ────────────────────────────────────────────
test_deny_revoked_device if {
    not allow with input as {
        "sub":       "bob-uuid",
        "device_id": "dev-revoked",
        "route":     "/api/v1/orders/123",
        "method":    "GET",
    }
    with http.send as mock_http_send_revoked
    with opa.runtime as mock_runtime
}

# ─── Test : raison du refus sur device révoqué ────────────────────────────────
test_deny_reason_revoked if {
    deny_reason == "device_revoked" with input as {
        "sub":       "bob-uuid",
        "device_id": "dev-revoked",
        "route":     "/api/v1/orders/123",
        "method":    "GET",
    }
    with http.send as mock_http_send_revoked
    with opa.runtime as mock_runtime
}

# ─── Test : raison du refus sur device suspendu ───────────────────────────────
test_deny_reason_suspended if {
    deny_reason == "device_suspended" with input as {
        "sub":       "bob-uuid",
        "device_id": "dev-suspended",
    }
    with http.send as mock_http_send_suspended
    with opa.runtime as mock_runtime
}

# ─── Test : low trust score deny reason ───────────────────────────────────────
test_deny_reason_low_trust if {
    deny_reason == "low_trust_score" with input as {
        "sub":       "bob-uuid",
        "device_id": "dev-software",
    }
    with http.send as mock_http_send_software
    with opa.runtime as mock_runtime
}

# ─── Test : deny reason signature invalide ────────────────────────────────────
test_deny_reason_signature_invalid if {
    deny_reason == "device_signature_invalid" with input as {
        "sub":            "bob-uuid",
        "device_id":      "dev-abc",
        "device_headers": mock_device_headers,
    }
    with http.send as mock_http_send_active_verify_fail
    with opa.runtime as mock_runtime
}

# ─── Test : deny reason signature manquante quand requise ─────────────────────
test_deny_reason_signature_missing if {
    deny_reason == "device_signature_missing" with input as {
        "sub":               "bob-uuid",
        "device_id":         "dev-abc",
        "require_signature": true,
    }
    with http.send as mock_http_send_active
    with opa.runtime as mock_runtime
}
