package ctxkeys

type contextKey string

const (
	UserID contextKey = "user_id"
	DeviceID        contextKey = "device_id"
	DeviceNonce     contextKey = "device_nonce"
	DeviceTimestamp contextKey = "device_timestamp"
	DeviceSignature contextKey = "device_signature"
	Token           contextKey = "token"
	Email           contextKey = "email"
	Acr             contextKey = "acr"
)
