package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"time"
)

// Minimal Docker Engine API client over the local unix socket — only what
// this agent needs (list running containers with their labels), no
// dependency beyond the Go standard library, same zero-dependency spirit as
// the rest of this project. Mirrors lib/docker.js#dockerCall() on the
// dashboard side in intent, not in code (different language, same idea: a
// tiny HTTP client dialing a unix socket instead of TCP).
type dockerClient struct {
	http *http.Client
}

func newDockerClient(socketPath string) *dockerClient {
	return &dockerClient{
		http: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					d := net.Dialer{}
					return d.DialContext(ctx, "unix", socketPath)
				},
			},
		},
	}
}

type dockerContainerSummary struct {
	ID     string            `json:"Id"`
	Names  []string          `json:"Names"`
	Labels map[string]string `json:"Labels"`
	State  string            `json:"State"`
}

// listRunningContainers returns every currently-running container's labels
// — that is all vhostFromLabels() needs; no separate "inspect" call required
// since /containers/json already returns Labels per container.
func (d *dockerClient) listRunningContainers(ctx context.Context) ([]dockerContainerSummary, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker/containers/json?filters=%7B%22status%22%3A%5B%22running%22%5D%7D", nil)
	if err != nil {
		return nil, err
	}
	resp, err := d.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("docker socket injoignable : %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("docker API a repondu %d", resp.StatusCode)
	}
	var out []dockerContainerSummary
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("reponse docker illisible : %w", err)
	}
	return out, nil
}
