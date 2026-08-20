package harbor

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

var (
	errBackendNotConfigured = errors.New("harbor backend is not configured")
	errRobotNotFound        = errors.New("robot account no longer exists")
)

type client struct {
	http     *http.Client
	url      string
	username string
	password string
}

func newClient(c *harborConfig) *client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if c.InsecureTLS {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}

	return &client{
		http:     &http.Client{Timeout: 30 * time.Second, Transport: transport},
		url:      strings.TrimSuffix(c.URL, "/"),
		username: c.Username,
		password: c.Password,
	}
}

type robotPermission struct {
	Kind      string         `json:"kind"`
	Namespace string         `json:"namespace"`
	Access    []robotAccess  `json:"access"`
}

type robotAccess struct {
	Resource string `json:"resource"`
	Action   string `json:"action"`
}

type robotRequest struct {
	Name        string            `json:"name"`
	Description string            `json:"description,omitempty"`
	Duration    int               `json:"duration"`
	Level       string            `json:"level"`
	Disable     bool              `json:"disable"`
	Permissions []robotPermission `json:"permissions"`
}

type robotResponse struct {
	ID     int    `json:"id"`
	Name   string `json:"name"`
	Secret string `json:"secret"`
}

func (c *client) do(ctx context.Context, method, path string, body any, out any) error {
	var payload io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return err
		}
		payload = bytes.NewReader(encoded)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.url+path, payload)
	if err != nil {
		return err
	}
	req.SetBasicAuth(c.username, c.password)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return errRobotNotFound
	}
	if resp.StatusCode >= 300 {
		detail, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("harbor returned %d: %s", resp.StatusCode, strings.TrimSpace(string(detail)))
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func (c *client) createRobot(ctx context.Context, req *robotRequest) (*robotResponse, error) {
	out := new(robotResponse)
	if err := c.do(ctx, http.MethodPost, "/api/v2.0/robots", req, out); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *client) deleteRobot(ctx context.Context, id int) error {
	return c.do(ctx, http.MethodDelete, fmt.Sprintf("/api/v2.0/robots/%d", id), nil, nil)
}

func (c *client) ping(ctx context.Context) error {
	return c.do(ctx, http.MethodGet, "/api/v2.0/robots?page_size=1", nil, nil)
}


func (c *client) findRobotByName(ctx context.Context, name string) (int, error) {
	const pageSize = 100
	for page := 1; ; page++ {
		var robots []robotResponse
		path := fmt.Sprintf("/api/v2.0/robots?page=%d&page_size=%d", page, pageSize)
		if err := c.do(ctx, http.MethodGet, path, nil, &robots); err != nil {
			return 0, err
		}
		for _, robot := range robots {
			if robot.Name == name || "robot$"+robot.Name == name {
				return robot.ID, nil
			}
		}
		if len(robots) < pageSize {
			return 0, fmt.Errorf("%w: %s", errRobotNotFound, name)
		}
	}
}

func (c *client) refreshRobotSecret(ctx context.Context, id int, secret string) error {
	body := map[string]any{"secret": secret}
	return c.do(ctx, http.MethodPatch, fmt.Sprintf("/api/v2.0/robots/%d", id), body, nil)
}
