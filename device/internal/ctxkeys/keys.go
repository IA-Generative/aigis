package ctxkeys

type contextKey string

const (
	UserID   contextKey = "user_id"
	DeviceID contextKey = "device_id"
	Email    contextKey = "email"
)
