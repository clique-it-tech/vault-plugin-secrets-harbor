package harbor

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	rootSecretLength = 32
	lowers           = "abcdefghijklmnopqrstuvwxyz"
	uppers           = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	digits           = "0123456789"
	alphabet         = lowers + uppers + digits
)

func pathRotateRoot(b *harborBackend) *framework.Path {
	return &framework.Path{
		Pattern: "config/rotate-root",
		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefixHarbor,
			OperationVerb:   "rotate",
			OperationSuffix: "root-credentials",
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{Callback: b.pathRotateRoot},
		},
		HelpSynopsis: "Replace the secret the engine authenticates with.",
		HelpDescription: `Generates a new secret for the configured robot account, sets it in Harbor
and stores it. Nobody, including the operator who first configured the engine, knows the secret
afterwards. Storage is written before Harbor so a failed rotation can be rolled back rather than
locking the engine out of the registry.`,
	}
}

func (b *harborBackend) pathRotateRoot(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	config, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if config == nil {
		return logical.ErrorResponse(errMissingConfig.Error()), nil
	}

	c, err := b.getClient(ctx, req.Storage)
	if err != nil {
		if errors.Is(err, errBackendNotConfigured) {
			return logical.ErrorResponse(errMissingConfig.Error()), nil
		}
		return nil, err
	}

	id, err := c.findRobotByName(ctx, config.Username)
	if err != nil {
		return nil, err
	}

	secret, err := generateSecret()
	if err != nil {
		return nil, err
	}

	previous := config.Password
	config.Password = secret
	if err := storeConfig(ctx, req.Storage, config); err != nil {
		return nil, err
	}

	if err := c.refreshRobotSecret(ctx, id, secret); err != nil {
		config.Password = previous
		if restoreErr := storeConfig(ctx, req.Storage, config); restoreErr != nil {
			return nil, fmt.Errorf(
				"harbor refused the new secret (%w) and the old one could not be put back (%w): "+
					"set a secret for robot %s by hand and write it to config",
				err, restoreErr, config.Username)
		}
		return nil, fmt.Errorf("could not set the new secret: %w", err)
	}

	b.reset()
	return nil, nil
}

func generateSecret() (string, error) {
	out := make([]byte, 0, rootSecretLength)
	for _, class := range []string{lowers, uppers, digits} {
		c, err := pick(class)
		if err != nil {
			return "", err
		}
		out = append(out, c)
	}
	for len(out) < rootSecretLength {
		c, err := pick(alphabet)
		if err != nil {
			return "", err
		}
		out = append(out, c)
	}

	for i := len(out) - 1; i > 0; i-- {
		j, err := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		if err != nil {
			return "", err
		}
		out[i], out[j.Int64()] = out[j.Int64()], out[i]
	}
	return string(out), nil
}

func pick(class string) (byte, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(len(class))))
	if err != nil {
		return 0, err
	}
	return class[n.Int64()], nil
}
