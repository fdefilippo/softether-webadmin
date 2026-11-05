package rpc

import "context"

// ServerInfo is the result of the GetServerInfo method (subset).
type ServerInfo struct {
	ProductName string `json:"ServerProductName_str"`
	Version     string `json:"ServerVersionString_str"`
	Build       string `json:"ServerBuildInfoString_str"`
	Hostname    string `json:"ServerHostName_str"`
	ServerType  uint32 `json:"ServerType_u32"`
	OsName      string `json:"OsProductName_str"`
}

// ServerStatus is the result of the GetServerStatus method (subset). The
// times are SoftEther date-time strings such as "2024-08-01T12:24:36.123".
type ServerStatus struct {
	NumSessions uint32 `json:"NumSessionsTotal_u32"`
	NumHubs     uint32 `json:"NumHubTotal_u32"`
	StartTime   string `json:"StartTime_dt"`
	CurrentTime string `json:"CurrentTime_dt"`
}

// Test calls the Test method, a no-op that only checks the credentials.
func (c *Client) Test(ctx context.Context, cred Credential) error {
	return c.Call(ctx, cred, "Test", map[string]any{"IntValue_u32": 0}, nil)
}

// GetServerInfo returns static information about the server.
func (c *Client) GetServerInfo(ctx context.Context, cred Credential) (ServerInfo, error) {
	var out ServerInfo
	err := c.Call(ctx, cred, "GetServerInfo", nil, &out)
	return out, err
}

// GetServerStatus returns the current server status.
func (c *Client) GetServerStatus(ctx context.Context, cred Credential) (ServerStatus, error) {
	var out ServerStatus
	err := c.Call(ctx, cred, "GetServerStatus", nil, &out)
	return out, err
}

// SetServerPassword sets the server administrator password. It is a write and
// is never retried.
func (c *Client) SetServerPassword(ctx context.Context, cred Credential, newPassword string) error {
	return c.Call(ctx, cred, "SetServerPassword", map[string]any{"PlainTextPassword_str": newPassword}, nil)
}
