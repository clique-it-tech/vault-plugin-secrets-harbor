package harbor

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const rolesStoragePrefix = "role/"

type harborRole struct {
	Project string        `json:"project"`
	Push    bool          `json:"push"`
	TTL     time.Duration `json:"ttl"`
	MaxTTL  time.Duration `json:"max_ttl"`
}

func (r *harborRole) toResponseData() map[string]any {
	return map[string]any{
		"project": r.Project,
		"push":    r.Push,
		"ttl":     int64(r.TTL.Seconds()),
		"max_ttl": int64(r.MaxTTL.Seconds()),
	}
}

func pathRoles(b *harborBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "roles/" + framework.GenericNameRegex("name"),
			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: operationPrefixHarbor,
				OperationSuffix: "role",
			},
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeLowerCaseString,
					Description: "Name of the role.",
					Required:    true,
				},
				"project": {
					Type:        framework.TypeString,
					Description: "Harbor project the issued accounts may act on.",
					Required:    true,
					DisplayAttrs: &framework.DisplayAttributes{
						Name:  "Project",
						Value: "clique",
					},
				},
				"push": {
					Type:        framework.TypeBool,
					Description: "Grant push in addition to pull.",
					Default:     false,
					DisplayAttrs: &framework.DisplayAttributes{
						Name: "Allow push",
					},
				},
				"ttl": {
					Type:        framework.TypeDurationSecond,
					Description: "Lifetime of an issued account.",
					DisplayAttrs: &framework.DisplayAttributes{
						Name:     "Lease",
						EditType: "ttl",
					},
				},
				"max_ttl": {
					Type:        framework.TypeDurationSecond,
					Description: "Longest an issued account may be renewed for.",
					DisplayAttrs: &framework.DisplayAttributes{
						Name:     "Longest lease",
						EditType: "ttl",
					},
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation:   &framework.PathOperation{Callback: b.pathRolesRead},
				logical.CreateOperation: &framework.PathOperation{Callback: b.pathRolesWrite},
				logical.UpdateOperation: &framework.PathOperation{Callback: b.pathRolesWrite},
				logical.DeleteOperation: &framework.PathOperation{Callback: b.pathRolesDelete},
			},
			ExistenceCheck:  b.pathRolesExistence,
			HelpSynopsis:    "Define what an issued robot account may do.",
			HelpDescription: "A policy can name one role, which is how access is narrowed to a single project.",
		},
		{
			Pattern: "roles/?$",
			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: operationPrefixHarbor,
				OperationSuffix: "roles",
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{Callback: b.pathRolesList},
			},
			HelpSynopsis: "List the defined roles.",
		},
	}
}

func getRole(ctx context.Context, s logical.Storage, name string) (*harborRole, error) {
	entry, err := s.Get(ctx, rolesStoragePrefix+name)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	role := new(harborRole)
	if err := entry.DecodeJSON(role); err != nil {
		return nil, err
	}
	return role, nil
}

func (b *harborBackend) pathRolesExistence(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	role, err := getRole(ctx, req.Storage, data.Get("name").(string))
	if err != nil {
		return false, err
	}
	return role != nil, nil
}

func (b *harborBackend) pathRolesRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	role, err := getRole(ctx, req.Storage, data.Get("name").(string))
	if err != nil {
		return nil, err
	}
	if role == nil {
		return nil, nil
	}
	return &logical.Response{Data: role.toResponseData()}, nil
}

func (b *harborBackend) pathRolesWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)

	role, err := getRole(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if role == nil {
		role = new(harborRole)
	}

	if project, ok := data.GetOk("project"); ok {
		role.Project = project.(string)
	}
	if push, ok := data.GetOk("push"); ok {
		role.Push = push.(bool)
	}
	if ttl, ok := data.GetOk("ttl"); ok {
		role.TTL = time.Duration(ttl.(int)) * time.Second
	}
	if maxTTL, ok := data.GetOk("max_ttl"); ok {
		role.MaxTTL = time.Duration(maxTTL.(int)) * time.Second
	}

	if role.Project == "" {
		return logical.ErrorResponse("project is required"), nil
	}
	if role.MaxTTL != 0 && role.TTL > role.MaxTTL {
		return logical.ErrorResponse("ttl cannot be longer than max_ttl"), nil
	}
	if role.MaxTTL > maxRobotLifetime {
		return logical.ErrorResponse(
			"max_ttl cannot exceed %s, which is how long the robot account itself lives",
			maxRobotLifetime), nil
	}

	entry, err := logical.StorageEntryJSON(rolesStoragePrefix+name, role)
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	return nil, nil
}

func (b *harborBackend) pathRolesDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	if err := req.Storage.Delete(ctx, rolesStoragePrefix+data.Get("name").(string)); err != nil {
		return nil, err
	}
	return nil, nil
}

func (b *harborBackend) pathRolesList(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	names, err := req.Storage.List(ctx, rolesStoragePrefix)
	if err != nil {
		return nil, err
	}
	return logical.ListResponse(names), nil
}

var errUnknownRole = errors.New("no such role")

func roleNotFound(name string) error {
	return fmt.Errorf("%w: %s", errUnknownRole, name)
}
