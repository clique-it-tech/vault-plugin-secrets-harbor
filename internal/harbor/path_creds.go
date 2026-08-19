package harbor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	robotExpiryDays  = 2
	maxRobotLifetime = 24 * time.Hour
)


func (b *harborBackend) robot() *framework.Secret {
	return &framework.Secret{
		Type: secretTypeRobot,
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "Full name of the robot account as Harbor knows it.",
			},
			"secret": {
				Type:        framework.TypeString,
				Description: "Password of the robot account.",
			},
		},
		Revoke: b.robotRevoke,
		Renew:  b.robotRenew,
	}
}

func pathCredentials(b *harborBackend) *framework.Path {
	return &framework.Path{
		Pattern: "creds/" + framework.GenericNameRegex("role"),
		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefixHarbor,
			OperationVerb:   "generate",
			OperationSuffix: "credentials",
		},
		Fields: map[string]*framework.FieldSchema{
			"role": {
				Type:        framework.TypeLowerCaseString,
				Description: "Role that decides which project the account may act on.",
				Required:    true,
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation:   &framework.PathOperation{Callback: b.pathCredentialsRead},
			logical.UpdateOperation: &framework.PathOperation{Callback: b.pathCredentialsRead},
		},
		HelpSynopsis:    "Issue a robot account for one role.",
		HelpDescription: "The project and the permissions come from the role, not from this request, so a policy that names one role cannot be used to reach another project.",
	}
}

func (b *harborBackend) pathCredentialsRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("role").(string)

	role, err := getRole(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return logical.ErrorResponse(roleNotFound(name).Error()), nil
	}

	c, err := b.getClient(ctx, req.Storage)
	if err != nil {
		if errors.Is(err, errBackendNotConfigured) {
			return logical.ErrorResponse(errMissingConfig.Error()), nil
		}
		return nil, err
	}

	access := []robotAccess{{Resource: "repository", Action: "pull"}}
	if role.Push {
		access = append(access, robotAccess{Resource: "repository", Action: "push"})
	}

	robotName := fmt.Sprintf("vault-%s-%d", name, time.Now().UnixNano())

	robot, err := c.createRobot(ctx, &robotRequest{
		Name:        robotName,
		Description: fmt.Sprintf("issued by vault for role %s, deleted when the lease ends", name),
		Duration:    robotExpiryDays,
		Level:       "project",
		Permissions: []robotPermission{{
			Kind:      "project",
			Namespace: role.Project,
			Access:    access,
		}},
	})
	if err != nil {
		return nil, fmt.Errorf("could not create the robot account: %w", err)
	}

	resp := b.Secret(secretTypeRobot).Response(
		map[string]any{
			"name":   robot.Name,
			"secret": robot.Secret,
		},
		map[string]any{
			"id":   robot.ID,
			"name": robot.Name,
		},
	)

	resp.Secret.TTL = role.TTL
	resp.Secret.MaxTTL = role.MaxTTL
	if resp.Secret.MaxTTL == 0 || resp.Secret.MaxTTL > maxRobotLifetime {
		resp.Secret.MaxTTL = maxRobotLifetime
	}

	return resp, nil
}

func (b *harborBackend) robotRevoke(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	raw, ok := req.Secret.InternalData["id"]
	if !ok {
		return nil, errors.New("lease is missing the robot id")
	}

	id, err := parseRobotID(raw)
	if err != nil {
		return nil, err
	}

	c, err := b.getClient(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	if err := c.deleteRobot(ctx, id); err != nil && !errors.Is(err, errRobotNotFound) {
		return nil, fmt.Errorf("could not delete the robot account: %w", err)
	}

	return nil, nil
}

func (b *harborBackend) robotRenew(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	resp := &logical.Response{Secret: req.Secret}
	resp.Secret.TTL = req.Secret.Increment
	return resp, nil
}

func parseRobotID(raw any) (int, error) {
	switch v := raw.(type) {
	case int:
		return v, nil
	case float64:
		return int(v), nil
	case json.Number:
		id, err := v.Int64()
		return int(id), err
	default:
		return 0, fmt.Errorf("unexpected robot id type %T", raw)
	}
}
