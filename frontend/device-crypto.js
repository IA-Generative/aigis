/**
 * device-crypto.js — Web Crypto API + device-bound session signatures
 * 
 * Gère :
 * - Génération de clé ECDSA P-256 dans IndexedDB (non-extractible si possible)
 * - Détection du niveau matériel (platform authenticator disponible ?)
 * - Signature de challenge / requête
 * - Export de la clé publique en PEM
 * - Headers X-Device-* pour device-bound sessions
 */
(() => {
	const DB_NAME = "device-crypto-keys";
	const STORE_NAME = "keys";
	const KEY_ID = "device-ecdsa-key";

	// ─── IndexedDB helpers ─────────────────────────────────────────────────────

	function openDB() {
		return new Promise((resolve, reject) => {
			const req = indexedDB.open(DB_NAME, 1);
			req.onupgradeneeded = () => req.result.createObjectStore(STORE_NAME);
			req.onsuccess = () => resolve(req.result);
			req.onerror = () => reject(req.error);
		});
	}

	async function storeKeyPair(keyPair) {
		const db = await openDB();
		return new Promise((resolve, reject) => {
			const tx = db.transaction(STORE_NAME, "readwrite");
			tx.objectStore(STORE_NAME).put(keyPair, KEY_ID);
			tx.oncomplete = () => resolve();
			tx.onerror = () => reject(tx.error);
		});
	}

	async function loadKeyPair() {
		const db = await openDB();
		return new Promise((resolve, reject) => {
			const tx = db.transaction(STORE_NAME, "readonly");
			const req = tx.objectStore(STORE_NAME).get(KEY_ID);
			req.onsuccess = () => resolve(req.result || null);
			req.onerror = () => reject(req.error);
		});
	}

	async function clearKeyPair() {
		const db = await openDB();
		return new Promise((resolve, reject) => {
			const tx = db.transaction(STORE_NAME, "readwrite");
			tx.objectStore(STORE_NAME).delete(KEY_ID);
			tx.oncomplete = () => resolve();
			tx.onerror = () => reject(tx.error);
		});
	}

	// ─── Key generation ────────────────────────────────────────────────────────

	/**
	 * Génère une paire de clés ECDSA P-256 dans le navigateur.
	 * extractable=false pour que la clé privée ne puisse pas être exportée.
	 * Stocke dans IndexedDB.
	 */
	async function generateKeyPair() {
		const keyPair = await crypto.subtle.generateKey(
			{ name: "ECDSA", namedCurve: "P-256" },
			false, // non-extractible : la clé privée ne peut pas être exportée
			["sign", "verify"]
		);
		await storeKeyPair(keyPair);
		return keyPair;
	}

	/**
	 * Retourne la paire de clés existante ou en génère une nouvelle.
	 */
	async function getOrCreateKeyPair() {
		let keyPair = await loadKeyPair();
		if (keyPair && keyPair.privateKey && keyPair.publicKey) {
			return keyPair;
		}
		return generateKeyPair();
	}

	// ─── Key export ────────────────────────────────────────────────────────────

	/**
	 * Exporte la clé publique en format PEM (SPKI)
	 */
	async function exportPublicKeyPEM(publicKey) {
		const spki = await crypto.subtle.exportKey("spki", publicKey);
		const b64 = arrayBufferToBase64(spki);
		const lines = b64.match(/.{1,64}/g).join("\n");
		return `-----BEGIN PUBLIC KEY-----\n${lines}\n-----END PUBLIC KEY-----`;
	}

	// ─── Signing ───────────────────────────────────────────────────────────────

	/**
	 * Signe un payload avec la clé privée ECDSA.
	 * @returns {string} signature en base64 (DER / ASN.1)
	 */
	async function signPayload(privateKey, payload) {
		const data = new TextEncoder().encode(payload);
		const signature = await crypto.subtle.sign(
			{ name: "ECDSA", hash: "SHA-256" },
			privateKey,
			data
		);
		return arrayBufferToBase64(signature);
	}

	/**
	 * Signe un challenge serveur (pour /verify ou /reattest)
	 */
	async function signChallenge(challenge) {
		const keyPair = await getOrCreateKeyPair();
		const nonce = crypto.randomUUID();
		const timestamp = new Date().toISOString();
		const payload = nonce + "|" + timestamp;
		const signature = await signPayload(keyPair.privateKey, payload);
		return {
			nonce,
			timestamp,
			signature,
			challenge
		};
	}

	/**
	 * Signe un challenge pré-enregistrement (FIDO2-style atomic ceremony).
	 * Le client signe le challenge brut (pas nonce|timestamp).
	 * @param {string} challenge - Le challenge reçu du serveur via /devices/register/challenge
	 * @returns {{ challenge: string, signature: string }}
	 */
	async function signRegisterChallenge(challenge) {
		const keyPair = await getOrCreateKeyPair();
		const signature = await signPayload(keyPair.privateKey, challenge);
		return {
			challenge,
			signature
		};
	}

	// ─── Device-bound session headers ──────────────────────────────────────────

	/**
	 * Génère les headers X-Device-* pour une requête authentifiée.
	 * Ajoute la preuve cryptographique que la requête vient de CE device.
	 * 
	 * @param {string} deviceId - L'ID du device
	 * @returns {Object} headers à ajouter à la requête fetch()
	 */
	async function makeDeviceHeaders(deviceId) {
		if (!deviceId) return {};

		try {
			const keyPair = await loadKeyPair();
			if (!keyPair || !keyPair.privateKey) return {};

			const nonce = crypto.randomUUID();
			const timestamp = new Date().toISOString();
			const payload = nonce + "|" + timestamp;
			const signature = await signPayload(keyPair.privateKey, payload);

			return {
				"X-Device-ID": deviceId,
				"X-Device-Nonce": nonce,
				"X-Device-Timestamp": timestamp,
				"X-Device-Signature": signature
			};
		} catch (err) {
			console.warn("Failed to create device headers:", err);
			return {};
		}
	}

	// ─── Hardware level detection ──────────────────────────────────────────────

	/**
	 * Détecte le niveau matériel disponible sur ce navigateur.
	 * Retourne : "tee" si un platform authenticator est dispo, "software" sinon.
	 */
	async function detectHardwareLevel() {
		try {
			if (!window.PublicKeyCredential) return { level: "software", provider: "software" };

			const available = await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
			if (available) {
				// On ne peut pas savoir exactement si c'est TPM, Secure Enclave, etc.
				// depuis le navigateur. On indique "tee" et le serveur validera.
				const platform = navigator.platform || "";
				let provider = "tee";
				if (/Mac|iPhone|iPad/.test(platform)) provider = "secure_enclave";
				if (/Win/.test(platform)) provider = "tpm";
				if (/Linux/.test(platform)) provider = "tpm";
				return { level: "tee", provider };
			}
			return { level: "software", provider: "software" };
		} catch (err) {
			console.warn("Hardware detection failed:", err);
			return { level: "software", provider: "software" };
		}
	}

	// ─── Utils ─────────────────────────────────────────────────────────────────

	function arrayBufferToBase64(buffer) {
		const bytes = new Uint8Array(buffer);
		let binary = "";
		bytes.forEach(b => binary += String.fromCharCode(b));
		return btoa(binary);
	}

	function base64ToArrayBuffer(b64) {
		const binary = atob(b64);
		const bytes = new Uint8Array(binary.length);
		for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
		return bytes.buffer;
	}

	// ─── Reset ─────────────────────────────────────────────────────────────────

	/**
	 * Supprime la clé privée locale (lors d'un reset ou révocation)
	 */
	async function resetKeys() {
		await clearKeyPair();
	}

	// ─── Export public API ─────────────────────────────────────────────────────

	window.DeviceCrypto = {
		getOrCreateKeyPair,
		generateKeyPair,
		exportPublicKeyPEM,
		signPayload,
		signChallenge,
		signRegisterChallenge,
		makeDeviceHeaders,
		detectHardwareLevel,
		resetKeys,
		loadKeyPair
	};
})();
