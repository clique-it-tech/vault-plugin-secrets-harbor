package harbor

import (
	"context"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	staticRoleStoragePrefix = "static-role/"
	staticRobotNamePrefix   = "vault-static-"
	// robotNeverExpires is what Harbor takes for an account with no expiry of
	// its own. A role nothing will rotate must not quietly die of old age.
	robotNeverExpires = -1
	// rotationExpiryMargin keeps Harbor's own expiry clear of the rotation
	// schedule, so a late rotation cannot arrive after the account is gone.
	rotationExpiryMargin = 7
)

type harborStaticRole struct {
	RobotID        int           `json:"robot_id"`
	RobotName      string        `json:"robot_name"`
	Secret         string        `json:"secret"`
	Project        string        `json:"project"`
	Push           bool          `json:"push"`
	LastRotation   time.Time     `json:"last_rotation"`
	RotationPeriod time.Duration `json:"rotation_period"`
}

func (r *harborStaticRole) nextRotation() time.Time {
	if r.RotationPeriod <= 0 {
		return time.Time{}
	}
	return r.LastRotation.Add(r.RotationPeriod)
}

// expiryDays keeps Harbor's own expiry a week clear of the rotation schedule.
// A role that nothing rotates gets no expiry at all: the alternative is an
// account that stops working on a day nobody chose.
func (r *harborStaticRole) expiryDays() int {
	if r.RotationPeriod <= 0 {
		return robotNeverExpires
	}
	return int(math.Ceil(r.RotationPeriod.Hours()/24)) + rotationExpiryMargin
}

func staticRoleNotFound(name string) error {
	return fmt.Errorf("no static role named %q", name)
}

func pathStaticRoles(b *harborBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "static-roles/?$",
			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: operationPrefixHarbor,
				OperationVerb:   "list",
				OperationSuffix: "static-roles",
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{Callback: b.pathStaticRolesList},
			},
			HelpSynopsis: "List the static roles.",
		},
		{
			Pattern: "static-roles/" + framework.GenericNameRegex("name"),
			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: operationPrefixHarbor,
				OperationSuffix: "static-role",
			},
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeLowerCaseString,
					Description: "Name of the static role.",
					Required:    true,
				},
				"project": {
					Type:        framework.TypeString,
					Description: "Harbor project the account may act on.",
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
				"rotation_period": {
					Type: framework.TypeDurationSecond,
					Description: "How often the engine replaces the account on its own. " +
						"Leave it out and it changes only when rotate-role is called.",
					DisplayAttrs: &framework.DisplayAttributes{
						Name:     "Rotate every",
						EditType: "ttl",
					},
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation:   &framework.PathOperation{Callback: b.pathStaticRoleRead},
				logical.CreateOperation: &framework.PathOperation{Callback: b.pathStaticRoleWrite},
				logical.UpdateOperation: &framework.PathOperation{Callback: b.pathStaticRoleWrite},
				logical.DeleteOperation: &framework.PathOperation{Callback: b.pathStaticRoleDelete},
			},
			ExistenceCheck: b.pathStaticRoleExistence,
			HelpSynopsis:   "Hold one robot account instead of issuing one per lease.",
			HelpDescription: `A role issues an account per lease, which suits a build job that asks
once and finishes. An image pull secret cannot work that way: it is read by every pod that starts,
and there is no lease to end. A static role holds one account, hands the same credential to every
reader, and replaces it on a schedule or on request.`,
		},
		{
			Pattern: "static-creds/" + framework.GenericNameRegex("name"),
			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: operationPrefixHarbor,
				OperationVerb:   "read",
				OperationSuffix: "static-credentials",
			},
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeLowerCaseString,
					Description: "Name of the static role.",
					Required:    true,
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{Callback: b.pathStaticCredsRead},
			},
			HelpSynopsis:    "Read the account a static role currently holds.",
			HelpDescription: "Reading creates nothing: the same name and secret come back until the role is rotated.",
		},
		{
			Pattern: "rotate-role/" + framework.GenericNameRegex("name"),
			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: operationPrefixHarbor,
				OperationVerb:   "rotate",
				OperationSuffix: "static-role",
			},
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeLowerCaseString,
					Description: "Name of the static role.",
					Required:    true,
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.UpdateOperation: &framework.PathOperation{Callback: b.pathStaticRoleRotate},
			},
			HelpSynopsis: "Replace the account a static role holds.",
			HelpDescription: `Harbor has no way to change a robot account's secret: the update action
does not exist for robots. Rotation therefore creates a second account and deletes the first, which
means the account name changes each time. Consumers must read the name alongside the secret.

The new account is created and stored before the old one is deleted, so a failure halfway leaves
the role holding credentials that work.`,
		},
	}
}

func staticRoleStoragePath(name string) string {
	return staticRoleStoragePrefix + name
}

func getStaticRole(ctx context.Context, s logical.Storage, name string) (*harborStaticRole, error) {
	entry, err := s.Get(ctx, staticRoleStoragePath(name))
	if err != nil || entry == nil {
		return nil, err
	}
	role := new(harborStaticRole)
	if err := entry.DecodeJSON(role); err != nil {
		return nil, err
	}
	return role, nil
}

func storeStaticRole(ctx context.Context, s logical.Storage, name string, role *harborStaticRole) error {
	entry, err := logical.StorageEntryJSON(staticRoleStoragePath(name), role)
	if err != nil {
		return err
	}
	return s.Put(ctx, entry)
}

func (b *harborBackend) pathStaticRoleExistence(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	role, err := getStaticRole(ctx, req.Storage, data.Get("name").(string))
	return role != nil, err
}

func (b *harborBackend) pathStaticRolesList(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	names, err := req.Storage.List(ctx, staticRoleStoragePrefix)
	if err != nil {
		return nil, err
	}
	return logical.ListResponse(names), nil
}

func (b *harborBackend) pathStaticRoleRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)
	role, err := getStaticRole(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return logical.ErrorResponse(staticRoleNotFound(name).Error()), nil
	}
	return &logical.Response{Data: map[string]any{
		"project":         role.Project,
		"push":            role.Push,
		"robot_name":      role.RobotName,
		"last_rotation":   role.LastRotation.Format(time.RFC3339),
		"rotation_period": int64(role.RotationPeriod.Seconds()),
	}}, nil
}

func (b *harborBackend) pathStaticRoleWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)

	role, err := getStaticRole(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if role == nil {
		role = new(harborStaticRole)
	}
	if project, ok := data.GetOk("project"); ok {
		role.Project = project.(string)
	}
	if push, ok := data.GetOk("push"); ok {
		role.Push = push.(bool)
	}
	if period, ok := data.GetOk("rotation_period"); ok {
		role.RotationPeriod = time.Duration(period.(int)) * time.Second
	}
	if role.Project == "" {
		return logical.ErrorResponse("project is required"), nil
	}

	dynamic, err := getRole(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if dynamic != nil {
		return logical.ErrorResponse(
			"a role named %q already exists; pick another name so a lease ending cannot delete the static account", name), nil
	}

	if role.RobotID == 0 {
		if err := b.replaceStaticRobot(ctx, req.Storage, name, role); err != nil {
			return nil, err
		}
		return nil, nil
	}
	return nil, storeStaticRole(ctx, req.Storage, name, role)
}

func (b *harborBackend) pathStaticCredsRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)
	role, err := getStaticRole(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return logical.ErrorResponse(staticRoleNotFound(name).Error()), nil
	}
	if role.RobotName == "" {
		return logical.ErrorResponse("static role %q holds no account yet; rotate it", name), nil
	}

	out := map[string]any{
		"name":          role.RobotName,
		"secret":        role.Secret,
		"last_rotation": role.LastRotation.Format(time.RFC3339),
	}
	if next := role.nextRotation(); !next.IsZero() {
		out["ttl"] = max(int64(0), int64(time.Until(next).Seconds()))
	}
	return &logical.Response{Data: out}, nil
}

func (b *harborBackend) pathStaticRoleRotate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)
	role, err := getStaticRole(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return logical.ErrorResponse(staticRoleNotFound(name).Error()), nil
	}
	if err := b.replaceStaticRobot(ctx, req.Storage, name, role); err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}
	return nil, nil
}

// rotateDueStaticRoles is what gives a rotation period meaning: Vault calls it
// on the active node about once a minute. A role that cannot be rotated is
// logged and skipped, so one broken role never stalls the rest.
func (b *harborBackend) rotateDueStaticRoles(ctx context.Context, req *logical.Request) error {
	names, err := req.Storage.List(ctx, staticRoleStoragePrefix)
	if err != nil {
		return err
	}

	for _, name := range names {
		role, err := getStaticRole(ctx, req.Storage, name)
		if err != nil || role == nil {
			continue
		}
		next := role.nextRotation()
		if next.IsZero() || time.Now().Before(next) {
			continue
		}
		if err := b.replaceStaticRobot(ctx, req.Storage, name, role); err != nil {
			b.Logger().Error("could not rotate static role", "role", name, "error", err)
		}
	}
	return nil
}

// replaceStaticRobot creates the replacement and records it before removing what
// it replaces. Harbor refuses two accounts with one name, so the new one carries
// a fresh suffix and the credential's name changes with every rotation.
func (b *harborBackend) replaceStaticRobot(ctx context.Context, s logical.Storage, name string, role *harborStaticRole) error {
	c, err := b.getClient(ctx, s)
	if err != nil {
		if errors.Is(err, errBackendNotConfigured) {
			return errMissingConfig
		}
		return err
	}

	access := []robotAccess{{Resource: "repository", Action: "pull"}}
	if role.Push {
		access = append(access, robotAccess{Resource: "repository", Action: "push"})
	}

	created, err := c.createRobot(ctx, &robotRequest{
		Name:        fmt.Sprintf("%s%s-%d", staticRobotNamePrefix, name, time.Now().UnixNano()),
		Description: fmt.Sprintf("held by vault for static role %s", name),
		Duration:    role.expiryDays(),
		Level:       "project",
		Permissions: []robotPermission{{
			Kind:      "project",
			Namespace: role.Project,
			Access:    access,
		}},
	})
	if err != nil {
		return fmt.Errorf("could not create the robot account: %w", err)
	}

	previousID, previousName := role.RobotID, role.RobotName
	role.RobotID, role.RobotName, role.Secret = created.ID, created.Name, created.Secret
	role.LastRotation = time.Now().UTC()
	if err := storeStaticRole(ctx, s, name, role); err != nil {
		return err
	}

	if previousID == 0 {
		return nil
	}
	if err := c.deleteRobot(ctx, previousID); err != nil && !errors.Is(err, errRobotNotFound) {
		return fmt.Errorf("the new account is in place, but %s could not be deleted: %w", previousName, err)
	}
	return nil
}

func (b *harborBackend) pathStaticRoleDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)
	role, err := getStaticRole(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return nil, nil
	}

	if role.RobotID != 0 {
		c, err := b.getClient(ctx, req.Storage)
		if err != nil {
			return nil, err
		}
		if err := c.deleteRobot(ctx, role.RobotID); err != nil && !errors.Is(err, errRobotNotFound) {
			return nil, fmt.Errorf("could not delete %s: %w", role.RobotName, err)
		}
	}
	return nil, req.Storage.Delete(ctx, staticRoleStoragePath(name))
}
