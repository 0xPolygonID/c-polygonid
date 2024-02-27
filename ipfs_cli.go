package c_polygonid

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"strings"
)

var defaultIPFSHttpCli = http.DefaultClient

type ipfsCli struct {
	rpcURL  string
	httpCli *http.Client
}

func (c *ipfsCli) Cat(path string) (io.ReadCloser, error) {
	rpcURL := strings.TrimRight(c.rpcURL, "/") + "/api/v0/cat?arg=" +
		url.QueryEscape(path)
	resp, err := c.getHttpCli().Post(rpcURL, "", http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("failed to send IPFS CAT request: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		return nil, fmt.Errorf("unexpected status code from IPFS RPC: %d",
			resp.StatusCode)
	}
	return resp.Body, nil
}

func (c *ipfsCli) Add(ctx context.Context, f io.Reader,
	name string) (string, error) {

	var requestBody bytes.Buffer
	writer := multipart.NewWriter(&requestBody)
	w, err := writer.CreateFormFile("file", name)
	if err != nil {
		return "", err
	}
	_, err = io.Copy(w, f)
	if err != nil {
		return "", err
	}
	err = writer.Close()
	if err != nil {
		return "", err
	}

	rpcURL := strings.TrimRight(c.rpcURL, "/") + "/api/v0/add"
	req, err := http.NewRequestWithContext(ctx, "POST", rpcURL, &requestBody)
	if err != nil {
		return "", err
	}

	req.Header.Set("Content-Type", writer.FormDataContentType())

	resp, err := c.getHttpCli().Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to send IPFS ADD request: %w", err)
	}

	defer func() { _ = resp.Body.Close() }()

	var rpcResp struct {
		Hash string `json:"Hash"`
	}
	err = json.NewDecoder(resp.Body).Decode(&rpcResp)
	if err != nil {
		return "", err
	}
	if rpcResp.Hash == "" {
		return "", errors.New("empty hash")
	}
	return rpcResp.Hash, nil
}

func (c *ipfsCli) getHttpCli() *http.Client {
	if c.httpCli == nil {
		return defaultIPFSHttpCli
	}
	return c.httpCli
}
