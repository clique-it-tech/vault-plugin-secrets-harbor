package harbor

import (
	"context"
	"errors"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const configStoragePath = "config"

type harborConfig struct {
	URL         string `json:"url"`
	Username    string `json:"username"`
	Password    string `json:"password"`
	InsecureTLS bool   `json:"insecure_tls"`
}

func pathConfig(b *harborBackend) *framework.Path {
	return &framework.Path{
		Pattern: "config",
		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefixHarbor,
		},
		Fields: map[string]*framework.FieldSchema{
			"url": {
				Type:        framework.TypeString,
				Description: "Base URL of the Harbor instance, without a trailing slash.",
				Required:    true,
			},
			"username": {
				Type:        framework.TypeString,
				Description: "Account allowed to create and delete robot accounts.",
				Required:    true,
			},
			"password": {
				Type:        framework.TypeString,
				Description: "Password for that account.",
				Required:    true,
				DisplayAttrs: &framework.DisplayAttributes{
					Sensitive: true,
				},
			},
			"insecure_tls": {
				Type:        framework.TypeBool,
				Description: "Skip verification of the Harbor certificate.",
				Default:     false,
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation:   &framework.PathOperation{Callback: b.pathConfigRead},
			logical.CreateOperation: &framework.PathOperation{Callback: b.pathConfigWrite},
			logical.UpdateOperation: &framework.PathOperation{Callback: b.pathConfigWrite},
			logical.DeleteOperation: &framework.PathOperation{Callback: b.pathConfigDelete},
		},
		ExistenceCheck:  b.pathConfigExistence,
		HelpSynopsis:    "Configure the Harbor instance this engine talks to.",
		HelpDescription: "The password is never returned once written.",
	}
}

func getConfig(ctx context.Context, s logical.Storage) (*harborConfig, error) {
	entry, err := s.Get(ctx, configStoragePath)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	config := new(harborConfig)
	if err := entry.DecodeJSON(config); err != nil {
		return nil, err
	}
	return config, nil
}

func storeConfig(ctx context.Context, s logical.Storage, config *harborConfig) error {
	entry, err := logical.StorageEntryJSON(configStoragePath, config)
	if err != nil {
		return err
	}
	return s.Put(ctx, entry)
}

func (b *harborBackend) pathConfigExistence(ctx context.Context, req *logical.Request, _ *framework.FieldData) (bool, error) {
	config, err := getConfig(ctx, req.Storage)
	if err != nil {
		return false, err
	}
	return config != nil, nil
}

func (b *harborBackend) pathConfigRead(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	config, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if config == nil {
		return nil, nil
	}

	return &logical.Response{
		Data: map[string]any{
			"url":          config.URL,
			"username":     config.Username,
			"insecure_tls": config.InsecureTLS,
		},
	}, nil
}

func (b *harborBackend) pathConfigWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	config, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if config == nil {
		config = new(harborConfig)
	}

	if url, ok := data.GetOk("url"); ok {
		config.URL = url.(string)
	}
	if username, ok := data.GetOk("username"); ok {
		config.Username = username.(string)
	}
	if password, ok := data.GetOk("password"); ok {
		config.Password = password.(string)
	}
	if insecure, ok := data.GetOk("insecure_tls"); ok {
		config.InsecureTLS = insecure.(bool)
	}

	if config.URL == "" || config.Username == "" || config.Password == "" {
		return logical.ErrorResponse("url, username and password are all required"), nil
	}

	if err := storeConfig(ctx, req.Storage, config); err != nil {
		return nil, err
	}

	b.reset()

	c, err := b.getClient(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if err := c.ping(ctx); err != nil {
		return logical.ErrorResponse("harbor rejected these credentials: %s", err), nil
	}

	return nil, nil
}

func (b *harborBackend) pathConfigDelete(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	if err := req.Storage.Delete(ctx, configStoragePath); err != nil {
		return nil, err
	}
	b.reset()
	return nil, nil
}

var errMissingConfig = errors.New("configure the engine at config before issuing credentials")
