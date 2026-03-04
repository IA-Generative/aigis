package cache

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/redis/go-redis/v9"
)

const DeviceStatusTTL = 30 * time.Second

type Redis struct {
	client *redis.Client
}

func NewRedis(url string) (*Redis, error) {
	opts, err := redis.ParseURL(url)
	if err != nil {
		return nil, err
	}

	client := redis.NewClient(opts)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		return nil, err
	}

	return &Redis{client: client}, nil
}

func (r *Redis) Close() error {
	return r.client.Close()
}

func (r *Redis) Ping(ctx context.Context) error {
	return r.client.Ping(ctx).Err()
}

func (r *Redis) SetDeviceStatus(ctx context.Context, deviceID string, status interface{}) error {
	data, err := json.Marshal(status)
	if err != nil {
		return err
	}
	return r.client.Set(ctx, deviceKey(deviceID), data, DeviceStatusTTL).Err()
}

func (r *Redis) GetDeviceStatus(ctx context.Context, deviceID string) ([]byte, error) {
	return r.client.Get(ctx, deviceKey(deviceID)).Bytes()
}

func (r *Redis) InvalidateDevice(ctx context.Context, deviceID string) error {
	return r.client.Del(ctx, deviceKey(deviceID)).Err()
}

func deviceKey(deviceID string) string {
	return "device:status:" + deviceID
}

// SetNonce marque un nonce comme utilisé avec un TTL
// pour prévenir les attaques par rejeu
func (r *Redis) SetNonce(ctx context.Context, nonce string, ttl time.Duration) error {
	return r.client.Set(ctx, nonceKey(nonce), "1", ttl).Err()
}

// GetNonce retourne true si le nonce a déjà été consommé
func (r *Redis) GetNonce(ctx context.Context, nonce string) (bool, error) {
	err := r.client.Get(ctx, nonceKey(nonce)).Err()
	if errors.Is(err, redis.Nil) {
		// Clé absente → nonce jamais vu, pas une erreur
		return false, nil
	}
	if err != nil {
		// Erreur Redis réelle
		return false, err
	}
	// Clé présente → nonce déjà utilisé
	return true, nil
}

func nonceKey(nonce string) string {
	return "nonce:" + nonce
}

// ─── Pre-registration challenge ────────────────────────────────────────────

const registerChallengePrefix = "register-challenge:"

// SetRegisterChallenge stocke un challenge pré-enregistrement dans Redis.
// Clé : register-challenge:{userID} → challenge string
func (r *Redis) SetRegisterChallenge(ctx context.Context, userID, challenge string, ttl time.Duration) error {
	return r.client.Set(ctx, registerChallengePrefix+userID, challenge, ttl).Err()
}

// GetRegisterChallenge récupère et supprime (consume) le challenge pré-enregistrement.
// Retourne le challenge ou "" si absent/expiré.
func (r *Redis) GetRegisterChallenge(ctx context.Context, userID string) (string, error) {
	key := registerChallengePrefix + userID
	challenge, err := r.client.Get(ctx, key).Result()
	if errors.Is(err, redis.Nil) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	// Consomme le challenge — usage unique
	r.client.Del(ctx, key)
	return challenge, nil
}

// ─── Pub/Sub : Cross-Device Approval Notifications ─────────────────────────

const approvalChannelPrefix = "device:approval:"

// PublishApprovalEvent publie un événement d'approbation/rejet sur le canal Redis
// d'un utilisateur. Tous les devices de cet utilisateur connectés en SSE le recevront.
func (r *Redis) PublishApprovalEvent(ctx context.Context, userID, message string) error {
	return r.client.Publish(ctx, approvalChannelPrefix+userID, message).Err()
}

// SubscribeApproval souscrit au canal d'approbation d'un utilisateur.
// Retourne un PubSub qui émet les messages d'approbation/rejet en temps réel.
func (r *Redis) SubscribeApproval(ctx context.Context, userID string) *redis.PubSub {
	return r.client.Subscribe(ctx, approvalChannelPrefix+userID)
}

// ─── Email challenge (Architecture B — cross-device via email) ─────────────

const emailChallengePrefix = "email-challenge:"

// SetEmailChallenge stores a one-time approval code for a pending device.
func (r *Redis) SetEmailChallenge(ctx context.Context, deviceID, code string, ttl time.Duration) error {
	return r.client.Set(ctx, emailChallengePrefix+deviceID, code, ttl).Err()
}

// GetAndDeleteEmailChallenge retrieves and atomically deletes the stored code.
// Returns "" if the key does not exist or has expired.
func (r *Redis) GetAndDeleteEmailChallenge(ctx context.Context, deviceID string) (string, error) {
	key := emailChallengePrefix + deviceID
	code, err := r.client.GetDel(ctx, key).Result()
	if errors.Is(err, redis.Nil) {
		return "", nil
	}
	return code, err
}
