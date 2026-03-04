(() => {
	const DEVICE_SERVICE_BASE_URL = "http://localhost:8080";
	const STORAGE_KEYS = {
		ACCESS_TOKEN: "device-service:access-token",
		DEVICE_ID: "device-service:last-device-id",
		OAUTH_PENDING: "device-service:oauth-pending"
	};

	async function api(url, options = {}) {
		const response = await fetch(url, options);
		if (!response.ok) {
			throw new Error(`${response.status} ${response.statusText} - ${JSON.stringify(response)}`);
		}
		try {
			return response.json()
		} catch (error) {
			console.warn("Response is not JSON", error);
			return response.text();
			// throw new Error(`${response.status} ${response.statusText} - ${JSON.stringify(data)}`);
		}
	}

	function b64Url(bytes) {
		let binary = "";
		bytes.forEach((b) => binary += String.fromCharCode(b));
		return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
	}

	function randomString(size = 32) {
		const bytes = new Uint8Array(size);
		crypto.getRandomValues(bytes);
		return b64Url(bytes);
	}

	async function sha256Base64Url(value) {
		const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
		return b64Url(new Uint8Array(digest));
	}

	function decodeJWT(token) {
		const parts = token.split(".");
		if (parts.length < 2) throw new Error("JWT invalide");
		const payload = parts[1].replace(/-/g, "+").replace(/_/g, "/");
		const padded = payload + "=".repeat((4 - (payload.length % 4)) % 4);
		return JSON.parse(atob(padded));
	}

	function isTokenExpired(token) {
		try {
			const decoded = decodeJWT(token);
			if (!decoded.exp) return true;
			const now = Math.floor(Date.now() / 1000);
			return decoded.exp <= now + 10;
		} catch (_) {
			return true;
		}
	}

	function clearOAuthQueryParams() {
		const url = new URL(window.location.href);
		["code", "state", "session_state", "iss", "error", "error_description", "error_uri"].forEach((name) => {
			url.searchParams.delete(name);
		});
		window.history.replaceState({}, "", url.toString());
	}

	function hasOAuthCallbackParams() {
		const params = new URLSearchParams(window.location.search);
		return params.has("code") || params.has("error");
	}

	function makeLogger(outputEl) {
		return function log(title, payload) {
			const text = typeof payload === "string" ? payload : JSON.stringify(payload, null, 2);
			outputEl.value = `\n=== ${title} ===\n${text}\n` + outputEl.value;
		};
	}

	function makeStatusSetter(statusEl) {
		return function setStatus(ok, msg) {
			statusEl.className = ok ? "ok" : "ko";
			statusEl.textContent = `Statut: ${msg}`;
		};
	}

	function makeDebugSetter(debugEl) {
		return function setDebug(payload) {
			debugEl.value = JSON.stringify(payload, null, 2);
		};
	}

	window.Common = {
		DEVICE_SERVICE_BASE_URL,
		STORAGE_KEYS,
		api,
		randomString,
		sha256Base64Url,
		decodeJWT,
		isTokenExpired,
		clearOAuthQueryParams,
		hasOAuthCallbackParams,
		makeLogger,
		makeStatusSetter,
		makeDebugSetter
	};
})();
