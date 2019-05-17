package crypto

import (
	"context"
	"encoding/base64"
	"fmt"

	kms "cloud.google.com/go/kms/apiv1"
	"github.com/pkg/errors"
	kmspb "google.golang.org/genproto/googleapis/cloud/kms/v1"
)

type Crypto interface {
	Encrypt(ctx context.Context, key, plainText string) (string, error)
	Decrypt(ctx context.Context, key, cipherText string) (string, error)
}

type crypto struct {
	kms *kms.KeyManagementClient
}

func NewService(ctx context.Context) (Crypto, error) {
	k, err := kms.NewKeyManagementClient(ctx)
	if err != nil {
		return nil, err
	}
	return &crypto{
		kms: k,
	}, nil
}

func (c *crypto) Encrypt(ctx context.Context, key, plainText string) (string, error) {
	resp, err := c.kms.Encrypt(ctx, &kmspb.EncryptRequest{
		Name:      key,
		Plaintext: []byte(plainText),
	})
	if err != nil {
		return "", errors.Wrapf(err, "kms: failed to encrypt. PlainText=%c", plainText)
	}
	t := base64.StdEncoding.EncodeToString(resp.Ciphertext)
	return t, nil
}

func (c *crypto) Decrypt(ctx context.Context, key, cipherText string) (string, error) {
	t, err := base64.StdEncoding.DecodeString(cipherText)
	if err != nil {
		return "", errors.Wrapf(err, "kms: failed base64 decode")
	}
	resp, err := c.kms.Decrypt(ctx, &kmspb.DecryptRequest{
		Name:       key,
		Ciphertext: t,
	})
	if err != nil {
		return "", errors.Wrapf(err, "kms: failed to decrypt. CipherText=%c", string(cipherText))
	}
	return string(resp.Plaintext), nil
}

// example keyName: "projects/PROJECT_ID/locations/global/keyRings/RING_ID/cryptoKeys/KEY_ID"
func Key(projectID, keyRingID, keyID string) string {
	return fmt.Sprintf("projects/%s/locations/global/keyRings/%s/cryptoKeys/%s", projectID, keyRingID, keyID)
}
