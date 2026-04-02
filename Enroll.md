# Device Enrollment & Attestation — Guide développeur

Ce document décrit le protocole complet d'enregistrement et d'attestation d'un device client dans le Device Service. Il s'adresse aux développeurs qui intègrent ce service dans une application native ou web.

---

## Table des matières

1. [Prérequis](#1-prérequis)
2. [Génération de la paire de clés](#2-génération-de-la-paire-de-clés)
3. [Enregistrement du device](#3-enregistrement-du-device)
4. [Politique d'approbation](#4-politique-dapprobation)
5. [Signature des requêtes API](#5-signature-des-requêtes-api)
6. [Re-attestation](#6-re-attestation)
7. [Trust Score](#7-trust-score)
8. [Endpoint de vérification](#8-endpoint-de-vérification)
9. [Référence des endpoints](#9-référence-des-endpoints)
10. [Recommandations de cybersécurité](#10-recommandations-de-cybersécurité)

---

## 1. Prérequis

### 1.1 Authentification OIDC/OAuth2

Toutes les routes protégées exigent un **Bearer JWT** valide émis par Keycloak via un flux Authorization Code + PKCE.

```
GET /api/discover
```

Cet endpoint retourne dynamiquement les URLs Keycloak configurées (authorization URLs, client ID) ainsi que les méthodes d'approbation actives.

```jsonc
// GET /api/discover — réponse
{
  "auth_url": "https://keycloak.example.com/realms/myapp/protocol/openid-connect/auth",
  "token_url": "https://keycloak.example.com/realms/myapp/protocol/openid-connect/token",
  "logout_url": "https://keycloak.example.com/realms/myapp/protocol/openid-connect/logout",
  "client_id": "device-service"
}
```

Le claim `sub` du JWT est utilisé comme `user_id` sur toutes les opérations. Le claim `email` est utilisé pour les notifications d'approbation. Le claim `acr` peut déclencher une approbation automatique selon la configuration serveur.

---

## 2. Génération de la paire de clés

### 2.1 Algorithme

Le service utilise **ECDSA P-256 (ES256)**. La clé publique doit être exportée au format **SPKI PEM**.

### 2.2 Implémentation Web Crypto (navigateur)

```js
// Générer une paire de clés non-extractable
const keyPair = await crypto.subtle.generateKey(
  { name: 'ECDSA', namedCurve: 'P-256' },
  false,               // clé privée non-extractable
  ['sign', 'verify']
)

// Exporter la clé publique au format SPKI PEM
async function exportPublicKeyPEM(publicKey) {
  const spki  = await crypto.subtle.exportKey('spki', publicKey)
  const b64   = btoa(String.fromCharCode(...new Uint8Array(spki)))
  const lines = b64.match(/.{1,64}/g).join('\n')
  return `-----BEGIN PUBLIC KEY-----\n${lines}\n-----END PUBLIC KEY-----`
}
```

> **Stockage de la clé privée** : Utilisez IndexedDB (navigateur) ou le Keystore/Secure Enclave de la plateforme. La clé privée ne doit jamais quitter le device.

### 2.3 Implémentation mobile / native

| Plateforme | API recommandée |
|---|---|
| Android | Android Keystore (StrongBox si disponible) |
| iOS / macOS | Secure Enclave via `SecKeyCreateRandomKey` |
| Linux / Windows | TPM 2.0 via PKCS#11 ou platform crypto |

Le champ `provider_name` envoyé lors de l'enregistrement doit refléter le mécanisme utilisé : `software`, `tpm`, `secure_enclave`, `tee`.

---

## 3. Enregistrement du device

L'enregistrement se déroule en **trois étapes** :

```
┌──────────┐          ┌──────────────────┐          ┌───────┐
│  Client  │          │   Device Service │          │ Redis │
└────┬─────┘          └────────┬─────────┘          └───┬───┘
     │                         │                        │
     │  POST /register/challenge (JWT)                  │
     │────────────────────────>│                        │
     │                         │── SetRegisterChallenge─>│
     │  { challenge, expires_in: 120 }                  │
     │<────────────────────────│                        │
     │                         │                        │
     │  [signe challenge avec clé privée]               │
     │                         │                        │
     │  POST /register (JWT + payload)                  │
     │────────────────────────>│                        │
     │                         │── GetRegisterChallenge──>│
     │                         │  VerifySignature ECDSA │
     │                         │── InvalidateChallenge──>│
     │  { device_id, status, trust_score }              │
     │<────────────────────────│                        │
```

### Étape 1 — Obtenir un challenge

```http
POST /api/devices/register/challenge
Authorization: Bearer <access_token>
```

**Réponse :**
```json
{
  "challenge": "a3f8c2d1e9b4...",
  "expires_in": 120
}
```

Le challenge expire après **2 minutes**. Il est lié au `user_id` extrait du JWT côté serveur.

### Étape 2 — Signer le challenge

Signez le challenge **brut** (la chaîne hex telle quelle) avec votre clé privée ECDSA P-256, hash SHA-256 :

```js
async function signRegisterChallenge(challenge, privateKey) {
  const data      = new TextEncoder().encode(challenge)
  const signature = await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    privateKey,
    data
  )
  return btoa(String.fromCharCode(...new Uint8Array(signature)))
}
```

Le format de signature accepté est **IEEE P1363** (raw `r || s`, produit nativement par Web Crypto) ou **DER/ASN.1** (OpenSSL, Go standard library).

### Étape 3 — Enregistrer le device

### 3.1 Enregistrement du device

```http
POST /api/devices/register
Authorization: Bearer <access_token>
Content-Type: application/json

{
  "device_id":            "",
  "name":                 "Mon MacBook Pro",
  "platform":             "macOS 14.4",
  "user_agent":           "Mozilla/5.0 ...",
  "public_key":           "-----BEGIN PUBLIC KEY-----\nMFkw...\n-----END PUBLIC KEY-----",
  "key_algorithm":        "ES256",
  "provider_name":        "software",
  "challenge":            "a3f8c2d1e9b4...",
  "challenge_signature":  "MEYCIQCx..."
}
```

**Réponse (device actif) :**
```json
{
  "device_id":      "550e8400-e29b-41d4-a716-446655440000",
  "device_status":  "active",
  "message":        "device registered",
  "trust_score":    70,
  "approval_methods": []
}
```

**Réponse (approbation requise) :**
```json
{
  "device_id":      "550e8400-e29b-41d4-a716-446655440000",
  "device_status":  "pending_approval",
  "message":        "device pending approval",
  "trust_score":    0,
  "approval_methods": ["email", "cross_device"]
}
```

### 3.2 Identifiant de device

Le `device_id` est le numéro unique du device. Cet identifiant doit être stocké de manière durable sur l'appareil et réutilisé à chaque session.

---

## 4. Politique d'approbation

Le statut initial d'un device enregistré dépend de la configuration serveur. Quatre chemins sont possibles, évalués dans cet ordre :

### 4.1 Auto-approbation (premier device)

Si `AUTO_APPROVE_FIRST_DEVICE=true` et que l'utilisateur n'a aucun device actif, le device est immédiatement `active`. `approved_by` vaut `auto:first_device`.

### 4.2 Approbation ACR

Si la méthode `acr` est activée et que la valeur du claim `acr` du JWT correspond exactement à `ACR_VALUES`, le device est immédiatement `active`. `approved_by` vaut `acr:<valeur>`.

### 4.3 Approbation par email (async)

Le device passe en `pending_approval`. Un code OTP à 6 chiffres est envoyé à l'email de l'utilisateur (TTL configurable, défaut 30 min).

Pour valider le code :
```http
POST /api/me/devices/{device_id}/verify-email
Authorization: Bearer <access_token>
Content-Type: application/json

{ "code": "123456" }
```

Pour redemander un code :
```http
POST /api/me/devices/{device_id}/renew-code
Authorization: Bearer <access_token>
```

### 4.4 Approbation cross-device

Un device actif appartenant au même utilisateur (avec un trust score ≥ `CROSS_DEVICE_MIN_TRUST`, défaut 50) peut approuver le nouveau device.

L'application doit écouter les événements SSE pour être notifiée en temps réel :

```http
GET /api/me/events
Authorization: Bearer <access_token>
Accept: text/event-stream
```

Événements reçus :
```
event: approval
data: {"type":"pending_device","device_id":"...","name":"Nouveau device","message":"Un nouveau device demande à être approuvé"}
```

Pour approuver depuis le device existant :
```http
POST /api/devices/{pending_device_id}/approve
Authorization: Bearer <access_token>
Content-Type: application/json

{ "approver_device_id": "<id_du_device_approbateur>" }
```

### 4.5 Cycle de vie du device

```
pending_approval ──approve──> active
pending_approval ──reject──> rejected
active ──revoke──> revoked
active / pending ──suspend──> suspended
```

Statuts possibles : `active`, `pending_approval`, `suspended`, `revoked`.

---

## 5. Signature des requêtes API

Une fois le device `active`, chaque appel API peut être signé cryptographiquement. Certains endpoints peuvent exiger cette signature selon la configuration serveur (`REQUIRE_DEVICE_SIGNATURE`).

### 5.1 Construction des headers

Le payload signé est : `nonce + "|" + timestamp` (chaîne UTF-8 concaténée avec le séparateur `|`).

```js
async function makeDeviceHeaders(deviceId, privateKey) {
  const nonce     = crypto.randomUUID()
  const timestamp = new Date().toISOString()        // RFC3339 / ISO 8601
  const payload   = nonce + '|' + timestamp
  const data      = new TextEncoder().encode(payload)
  const sig       = await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    privateKey,
    data
  )
  const signature = btoa(String.fromCharCode(...new Uint8Array(sig)))

  return {
    'X-Device-ID':        deviceId,
    'X-Device-Nonce':     nonce,
    'X-Device-Timestamp': timestamp,
    'X-Device-Signature': signature,
  }
}
```

### 5.2 Règles de validation côté serveur

| Contrôle | Valeur |
|---|---|
| Fenêtre temporelle | ±30 secondes autour du timestamp |
| Anti-replay (nonce) | Nonce consommé immédiatement, TTL 60 s |
| Liaison user | `device.user_id` doit correspondre au `sub` du JWT |
| Statut device | Doit être `active` |

> Un nonce ne peut être utilisé qu'**une seule fois**. Générez un UUID v4 cryptographique à chaque requête.

### 5.3 Exemple de requête complète

```http
GET /api/verify
Authorization: Bearer <access_token>
X-Device-ID: 550e8400-e29b-41d4-a716-446655440000
X-Device-Nonce: f47ac10b-58cc-4372-a567-0e02b2c3d479
X-Device-Timestamp: 2026-04-01T14:22:31Z
X-Device-Signature: MEYCIQCx...
```

**Réponse :**
```json
{
  "device_id":    "550e8400-e29b-41d4-a716-446655440000",
  "user_id":      "auth0|abc123",
  "verified":     true,
  "trust_score":  85,
  "status":       "active",
  "device_signed": true,
  "message":      ""
}
```

---

## 6. Re-attestation

La re-attestation permet de rafraîchir la preuve cryptographique du device et d'augmenter son trust score. Elle suit un protocole challenge-réponse propre :

```
1. Client  →  POST /api/devices/{id}/challenge          (JWT requis)
              ← { challenge: "...", expires_in: 120 }

2. Client signe : payload = nonce + "|" + timestamp
   (indépendamment du challenge retourné, qui sert d'ancre temporelle)

3. Client  →  POST /api/devices/{id}/reattest
              { nonce, timestamp, signature, public_key, key_algorithm, provider_name }
              ← { reattested: true, device_id: "...", trust_score: 90 }
```

```http
POST /api/devices/{device_id}/reattest
Authorization: Bearer <access_token>
Content-Type: application/json

{
  "nonce":         "f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "timestamp":     "2026-04-01T14:22:31Z",
  "signature":     "MEYCIQCx...",
  "public_key":    "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----",
  "key_algorithm": "ES256",
  "provider_name": "secure_enclave"
}
```

Il est recommandé de re-attester selon l'intervalle `REATTEST_INTERVAL_HOURS` (défaut 24 h) pour maintenir le trust score maximal.

---

## 7. Trust Score

Le trust score est calculé dynamiquement (0–100) à chaque évaluation, selon cinq critères :

| Critère | Points |
|---|---|
| **Méthode d'approbation** | Premier device / cross-device : 30 pts — ACR : 25 pts — Email : 20 pts |
| **Clé publique enregistrée** | +25 pts si `public_key` présent |
| **Fraîcheur d'attestation** | +15 pts (<1 h), +10 pts (<interval), 0 pt (<7 j), -10 pts (>7 j) |
| **Compteur de re-attestations** | +5 pts (≥1), +10 pts (≥5), +15 pts (≥10) |
| **Activité récente** | +10 pts (<1 h), +5 pts (<24 h) |
| **Statut** | `active` : +5 pts — tout autre statut : -100 pts |

Consultez le score à tout moment :
```http
GET /api/devices/{device_id}/trust
Authorization: Bearer <access_token>
```

```json
{
  "device_id":   "550e8400-...",
  "trust_score": 85,
  "breakdown": {
    "approval_method_points":  30,
    "signature_points":        25,
    "attestation_age_points":  15,
    "reattest_count_points":   10,
    "activity_points":          5,
    "status_points":            5
  }
}
```

---

## 8. Endpoint de vérification

L'endpoint `/api/verify` est le point d'entrée pour valider l'identité d'un device. Il accepte deux modes :

### Mode headers (GET)

Signature dans les headers `X-Device-*` (voir §5) :
```http
GET /api/verify
Authorization: Bearer <access_token>
X-Device-ID: ...
X-Device-Nonce: ...
X-Device-Timestamp: ...
X-Device-Signature: ...
```

### Mode body (POST)

Signature dans le corps JSON :
```http
POST /api/verify
Authorization: Bearer <access_token>
Content-Type: application/json

{
  "device_id":  "550e8400-...",
  "nonce":      "f47ac10b-...",
  "timestamp":  "2026-04-01T14:22:31Z",
  "signature":  "MEYCIQCx..."
}
```

### Mode API key

Pour les appels machine-to-machine sans JWT :
```http
GET /api/verify
X-API-KEY: <api_key>
```

### Headers de réponse

Quelle que soit la méthode, les headers de réponse suivants sont toujours présents :

| Header | Valeur |
|---|---|
| `X-Verified` | `true` / `false` |
| `X-Trust-Score` | Entier 0–100 |
| `X-Device-Signed` | `true` si une clé publique est enregistrée |

---

## 9. Référence des endpoints

### Enregistrement

| Méthode | Endpoint | Auth | Description |
|---|---|---|---|
| `POST` | `/api/devices/register/challenge` | JWT | Génère un challenge pré-enregistrement (TTL 2 min) |
| `POST` | `/api/devices/register` | JWT | Enregistre le device avec clé publique et signature |

### Gestion du device

| Méthode | Endpoint | Auth | Description |
|---|---|---|---|
| `GET` | `/api/devices/{id}` | JWT | Détails complets du device |
| `GET` | `/api/devices/{id}/status` | JWT | Statut et trust score |
| `GET` | `/api/devices/{id}/trust` | JWT | Trust score détaillé avec breakdown |
| `POST` | `/api/devices/{id}/revoke` | JWT | Révoque le device |
| `POST` | `/api/devices/{id}/approve` | JWT | Approuve un device en attente (cross-device) |
| `POST` | `/api/devices/{id}/reject` | JWT | Rejette un device en attente |

### Attestation

| Méthode | Endpoint | Auth | Description |
|---|---|---|---|
| `POST` | `/api/devices/{id}/challenge` | JWT | Génère un challenge de re-attestation (TTL 2 min) |
| `POST` | `/api/devices/{id}/reattest` | JWT | Soumet une re-attestation signée |

### Espace personnel

| Méthode | Endpoint | Auth | Description |
|---|---|---|---|
| `GET` | `/api/me/devices` | JWT | Liste tous mes devices |
| `GET` | `/api/me/devices/pending` | JWT | Liste mes devices en attente |
| `GET` | `/api/me/events` | JWT | SSE — événements d'approbation en temps réel |
| `POST` | `/api/me/devices/{id}/verify-email` | JWT | Valide le code OTP reçu par email |
| `POST` | `/api/me/devices/{id}/renew-code` | JWT | Redemande un code OTP par email |

### Vérification & infrastructure

| Méthode | Endpoint | Auth | Description |
|---|---|---|---|
| `GET/POST` | `/api/verify` | JWT / API Key | Vérifie la signature device |
| `GET` | `/api/discover` | Aucune | Découverte de la configuration |
| `GET` | `/healthz` | Aucune | Liveness probe |
| `GET` | `/readyz` | Aucune | Readiness probe |

---

## 10. Recommandations de cybersécurité

### Gestion des clés

**Clé privée non-extractable.** Générez la clé avec `extractable: false` (Web Crypto) ou stockez-la dans un hardware-backed keystore (Android Keystore avec StrongBox, iOS Secure Enclave, TPM). La clé privée ne doit jamais transiter sur le réseau ni être sérialisée en clair.

**Rotation des clés.** Prévoyez un mécanisme de re-génération de la paire de clés (par exemple lors d'une réinitialisation d'usine ou d'une compromission détectée). Après rotation, déclenchez immédiatement une re-attestation.

**Destruction sécurisée.** Lors de la révocation ou de la désinscription du device, supprimez explicitement la clé du keystore. Sur IndexedDB, appelez `clearKeyPair()` et invalidez le device côté API.

### Protocole d'enregistrement

**Ne jamais réutiliser un challenge.** Le challenge est à usage unique (stocké en Redis, invalidé après vérification). Si la signature échoue, redemandez un nouveau challenge.

**Vérifier le TTL du challenge.** Le challenge expire après 2 minutes. Votre implémentation doit gérer l'expiration et retenter proprement plutôt que de conserver un challenge périmé.

**Lier le challenge à l'utilisateur.** Le challenge de pré-enregistrement est lié au `user_id` du JWT. N'acceptez jamais un challenge provenant d'une autre session.

### Signatures de requêtes

**Nonce cryptographique.** Utilisez `crypto.randomUUID()` ou équivalent cryptographiquement sûr. N'utilisez jamais un compteur séquentiel ou un timestamp seul comme nonce.

**Fenêtre temporelle stricte.** Le serveur rejette toute signature avec un timestamp décalé de plus de 30 secondes. Synchronisez l'horloge du client (NTP) et construisez le timestamp immédiatement avant la signature, pas à l'avance.

**Consommation du nonce.** Chaque nonce est marqué "utilisé" dès réception côté serveur (TTL 60 s). Ne réutilisez jamais un nonce, même en cas de retry d'une requête.

### Transport

**HTTPS obligatoire.** Toutes les communications doivent passer par TLS 1.2 minimum. Ne faites jamais de fallback HTTP en production.

**Certificate pinning.** Sur les applications mobiles, activez le certificate pinning pour prévenir les attaques MITM.

**Validation de la réponse.** Vérifiez que `verified: true` ET que `status: "active"` sont présents dans la réponse `/api/verify` avant d'accorder l'accès. Un trust score seul ne suffit pas.

### Stockage côté client

**device_id persistant.** Stockez le `device_id` dans un espace de stockage sécurisé et persistant (Keychain iOS, EncryptedSharedPreferences Android, localStorage chiffré). Sa perte force un nouveau cycle d'enregistrement.

**Tokens JWT.** Ne stockez jamais les access tokens dans localStorage en production web. Préférez les cookies `HttpOnly; Secure; SameSite=Strict` ou la mémoire applicative.

### Révocation et incidents

**Révocation immédiate.** En cas de compromise détectée (device volé, anomalie comportementale), appelez `POST /api/devices/{id}/revoke` depuis un device de confiance. L'invalidation du cache Redis est immédiate.

**Surveillance des devices actifs.** Exposez à vos utilisateurs la liste de leurs devices actifs (`GET /api/me/devices`) pour leur permettre de détecter et révoquer tout device non reconnu.

**Re-attestation régulière.** Planifiez une re-attestation périodique (au moins toutes les `REATTEST_INTERVAL_HOURS`, défaut 24 h). Un device qui n'a pas re-attesté depuis plus de 7 jours voit son trust score diminuer de 10 points en raison du critère de fraîcheur d'attestation.