package ctxkeys

type contextKey string

const (
	UserID          contextKey = "user_id"
	DeviceID        contextKey = "device_id"
	DeviceNonce     contextKey = "device_nonce"
	DeviceTimestamp contextKey = "device_timestamp"
	DeviceSignature contextKey = "device_signature"
	Token           contextKey = "token"
	Email           contextKey = "email"
	Acr             contextKey = "acr"
	ForwardedFor    contextKey = "forwarded_for"
)

type headerKey string

const (
	HeaderXDeviceID        headerKey = "X-Device-ID"
	HeaderXDeviceNonce     headerKey = "X-Device-Nonce"
	HeaderXDeviceTimestamp headerKey = "X-Device-Timestamp"
	HeaderXDeviceSignature headerKey = "X-Device-Signature"
	HeaderXForwardedFor    headerKey = "X-Forwarded-For"
	HeaderXApiKey          headerKey = "X-Api-Key"
	HeaderXUserID          headerKey = "X-User-ID"
	HeaderXServiceID       headerKey = "X-Service-ID"
	HeaderAuthorization    headerKey = "Authorization"
	HeaderXVerified        headerKey = "X-Device-Verified"
	HeaderXDeviceStatus    headerKey = "X-Device-Status"
	HeaderXDeviceSigned    headerKey = "X-Device-Signed"
	HeaderXTrustScore      headerKey = "X-Trust-Score"
)
