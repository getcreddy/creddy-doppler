package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	sdk "github.com/getcreddy/creddy-plugin-sdk"
)

const (
	PluginName    = "doppler"
	PluginVersion = "0.1.0"
)

// DopplerPlugin implements the Creddy Plugin interface for Doppler
type DopplerPlugin struct {
	config *DopplerConfig
}

// DopplerConfig contains the plugin configuration
type DopplerConfig struct {
	Token string `json:"token"` // Personal or service account token
}

// dopplerServiceToken represents a service token from the API
type dopplerServiceToken struct {
	Name      string    `json:"name"`
	Slug      string    `json:"slug"`
	Key       string    `json:"key"` // Only returned on creation
	Project   string    `json:"project"`
	Config    string    `json:"config"`
	Access    string    `json:"access"` // "read" or "read/write"
	ExpiresAt time.Time `json:"expires_at,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

func (p *DopplerPlugin) Info(ctx context.Context) (*sdk.PluginInfo, error) {
	return &sdk.PluginInfo{
		Name:             PluginName,
		Version:          PluginVersion,
		Description:      "Scoped Doppler service tokens for secrets access",
		MinCreddyVersion: "0.4.0",
	}, nil
}

func (p *DopplerPlugin) Scopes(ctx context.Context) ([]sdk.ScopeSpec, error) {
	return []sdk.ScopeSpec{
		{
			Pattern:     "doppler:<project>/<config>",
			Description: "Access to secrets in a specific project/config",
			Examples:    []string{"doppler:myproject/production", "doppler:myproject/staging:read"},
		},
		{
			Pattern:     "doppler:<project>/*",
			Description: "Access to all configs in a project",
			Examples:    []string{"doppler:myproject/*", "doppler:myproject/*:read"},
		},
	}, nil
}

func (p *DopplerPlugin) Configure(ctx context.Context, configJSON string) error {
	var config DopplerConfig
	if err := json.Unmarshal([]byte(configJSON), &config); err != nil {
		return fmt.Errorf("invalid config JSON: %w", err)
	}

	if config.Token == "" {
		return fmt.Errorf("token is required")
	}

	p.config = &config
	return nil
}

func (p *DopplerPlugin) Validate(ctx context.Context) error {
	if p.config == nil {
		return fmt.Errorf("plugin not configured")
	}

	// Test the token by listing projects
	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.doppler.com/v3/projects", nil)
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", "Bearer "+p.config.Token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to validate token: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return fmt.Errorf("invalid token")
	}
	if resp.StatusCode == http.StatusForbidden {
		return fmt.Errorf("token does not have permission to list projects")
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("doppler API error (%d): %s", resp.StatusCode, string(body))
	}

	return nil
}

func (p *DopplerPlugin) GetCredential(ctx context.Context, req *sdk.CredentialRequest) (*sdk.Credential, error) {
	if p.config == nil {
		return nil, fmt.Errorf("plugin not configured")
	}

	// Parse scope: doppler:project/config or doppler:project/config:read
	project, config, access := parseDopplerScope(req.Scope)
	if project == "" || config == "" {
		return nil, fmt.Errorf("invalid doppler scope: %s (expected doppler:project/config)", req.Scope)
	}

	// Create service token
	name := fmt.Sprintf("creddy-%s-%d", req.Agent.Name, time.Now().UnixNano())
	expiresAt := time.Now().Add(req.TTL)

	serviceToken, err := p.createServiceToken(ctx, project, config, name, access, &expiresAt)
	if err != nil {
		return nil, err
	}

	// External ID format: project/config/slug (for deletion)
	externalID := fmt.Sprintf("%s/%s/%s", project, config, serviceToken.Slug)

	return &sdk.Credential{
		Value:      serviceToken.Key,
		ExternalID: externalID,
		ExpiresAt:  expiresAt,
		Metadata: map[string]string{
			"project": project,
			"config":  config,
			"slug":    serviceToken.Slug,
			"access":  access,
		},
	}, nil
}

func (p *DopplerPlugin) RevokeCredential(ctx context.Context, externalID string) error {
	if p.config == nil {
		return fmt.Errorf("plugin not configured")
	}

	// Parse external ID: project/config/slug
	project, config, slug := parseDopplerExternalID(externalID)
	if project == "" || config == "" || slug == "" {
		return fmt.Errorf("invalid external ID format: %s", externalID)
	}

	return p.deleteServiceToken(ctx, project, config, slug)
}

func (p *DopplerPlugin) MatchScope(ctx context.Context, scope string) (bool, error) {
	return strings.HasPrefix(scope, "doppler:"), nil
}

// --- Doppler API helpers ---

func (p *DopplerPlugin) createServiceToken(ctx context.Context, project, config, name, access string, expiresAt *time.Time) (*dopplerServiceToken, error) {
	body := map[string]interface{}{
		"name":    name,
		"project": project,
		"config":  config,
		"access":  access,
	}
	if expiresAt != nil {
		body["expire_at"] = expiresAt.Format(time.RFC3339)
	}

	reqBody, _ := json.Marshal(body)

	req, err := http.NewRequestWithContext(ctx, "POST", "https://api.doppler.com/v3/configs/config/tokens", bytes.NewReader(reqBody))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+p.config.Token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to create service token: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("doppler API error (%d): %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		Token dopplerServiceToken `json:"token"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &result.Token, nil
}

func (p *DopplerPlugin) deleteServiceToken(ctx context.Context, project, config, slug string) error {
	url := fmt.Sprintf("https://api.doppler.com/v3/configs/config/tokens/token?project=%s&config=%s&slug=%s",
		project, config, slug)

	req, err := http.NewRequestWithContext(ctx, "DELETE", url, nil)
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", "Bearer "+p.config.Token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to delete service token: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusNotFound {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("doppler API error (%d): %s", resp.StatusCode, string(body))
	}

	return nil
}

// parseDopplerScope parses "doppler:project/config" or "doppler:project/config:read"
func parseDopplerScope(scope string) (project, config, access string) {
	if !strings.HasPrefix(scope, "doppler:") {
		return "", "", ""
	}

	rest := strings.TrimPrefix(scope, "doppler:")
	access = "read/write" // default

	// Check for :read suffix
	if strings.HasSuffix(rest, ":read") {
		rest = strings.TrimSuffix(rest, ":read")
		access = "read"
	} else if strings.HasSuffix(rest, ":write") {
		rest = strings.TrimSuffix(rest, ":write")
		access = "read/write"
	}

	// Parse project/config
	parts := strings.SplitN(rest, "/", 2)
	if len(parts) == 2 {
		return parts[0], parts[1], access
	}
	return "", "", ""
}

// parseDopplerExternalID parses "project/config/slug"
func parseDopplerExternalID(id string) (project, config, slug string) {
	parts := strings.SplitN(id, "/", 3)
	if len(parts) >= 3 {
		return parts[0], parts[1], parts[2]
	}
	return "", "", ""
}
