package harbor

import (
	"context"
	"strings"
	"sync"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	operationPrefixHarbor = "harbor"
	secretTypeRobot       = "harbor_robot"
)

func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := backend()
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}

type harborBackend struct {
	*framework.Backend
	lock   sync.RWMutex
	client *client
}

func backend() *harborBackend {
	b := &harborBackend{}

	b.Backend = &framework.Backend{
		Help: strings.TrimSpace(backendHelp),
		PathsSpecial: &logical.Paths{
			SealWrapStorage: []string{configStoragePath, rolesStoragePrefix + "*"},
		},
		Paths: framework.PathAppend(
			pathRoles(b),
			[]*framework.Path{
				pathConfig(b),
				pathCredentials(b),
			},
		),
		Secrets: []*framework.Secret{
			b.robot(),
		},
		BackendType:    logical.TypeLogical,
		Invalidate:     b.invalidate,
	}

	return b
}

func (b *harborBackend) invalidate(ctx context.Context, key string) {
	if key == configStoragePath {
		b.reset()
	}
}

func (b *harborBackend) reset() {
	b.lock.Lock()
	defer b.lock.Unlock()
	b.client = nil
}

func (b *harborBackend) getClient(ctx context.Context, s logical.Storage) (*client, error) {
	b.lock.RLock()
	if b.client != nil {
		defer b.lock.RUnlock()
		return b.client, nil
	}
	b.lock.RUnlock()

	b.lock.Lock()
	defer b.lock.Unlock()
	if b.client != nil {
		return b.client, nil
	}

	config, err := getConfig(ctx, s)
	if err != nil {
		return nil, err
	}
	if config == nil {
		return nil, errBackendNotConfigured
	}

	b.client = newClient(config)
	return b.client, nil
}

const backendHelp = `
The Harbor secrets engine issues robot accounts on demand. Every account is
bound to a Vault lease and is deleted from Harbor when that lease ends, so a
leaked credential stops working as soon as the lease is revoked rather than
when Harbor's own expiry is reached.
`
